# Chương 8 — Bàn luận và hạn chế

> Chương này diễn giải ý nghĩa của kết quả (Chương 7) trong khung câu hỏi nghiên cứu (Chương 1), rồi nêu các hạn chế trung thực của kho tại thời điểm báo cáo.

## 8.1. Diễn giải kết quả theo câu hỏi nghiên cứu

### 8.1.1. CH1 — Logic tất định giữ quyền quyết định

Kết quả D2 và mục 7.4 ủng hộ CH1. Trên 4.38 triệu dòng, verdict luôn do rules quyết định (MATCHED/EMPTY), và judge LLM chỉ chạy sau khi đã có hàng; khi không có hàng, judge từ chối gọi LLM và trả NO_SIGNAL với 0 token. Tính non-deterministic của judge (mục 7.3.1) — cùng bằng chứng cho 0.82/0.85/0.87 — cho thấy rõ vì sao judge **không được** làm verdict chính: nếu để LLM quyết định, kết luận sẽ dao động giữa các lần chạy. Kiến trúc đặt LLM ở tầng đề xuất (tầng 2, Chương 4) là câu trả lời trực tiếp cho CH1.

### 8.1.2. CH2 — Ánh xạ PEAK mà không đánh mất bản chất

Chương 3 và Chương 5 ủng hộ CH2. Hệ thống hiện thực hóa bốn cửa PEAK trên đường PoC, và với đóng góp mới, ép Prepare thành cổng bắt buộc trên mọi đường săn. Điểm tinh tế: cổng **suy plan tự động** khi hunt đã mang đủ mục tiêu, thay vì bắt người dùng viết plan cho mọi lệnh — điều này giữ được tinh thần PEAK "không hunt nào không có Prepare" mà không biến quy trình thành gánh nặng thủ tục. Kết quả D4 (3/3 kịch bản đúng) và D1 (0 hồi quy) xác nhận cổng hoạt động đúng và không phá luồng cũ.

### 8.1.3. CH3 — Độ đặc hiệu cao, độ nhạy có, đo được một phần

Kết quả D2 (0 FP) và D3 (Joomla MATCHED) cho thấy hệ thống phát hiện được tấn công thật mà không báo bừa trên nhiễu lành tính — trả lời khẳng định cho CH3 *trong phạm vi đã đo*. Tuy nhiên, "đo được đến đâu" là phần cần trung thực: recall mới đo được **một chặng** (Joomla web), và không có số F1 tổng quát. Chi tiết ở mục 8.2.

## 8.2. Hạn chế trung thực

Các hạn chế sau là sự thật của kho tại thời điểm báo cáo, bám sát checklist và mã. Chúng được nêu để báo cáo không quá đà.

1. **Recall mới đo được một chặng.** Chỉ chặng Joomla web đo được recall. Các chặng khác (failed-logon 4625, encoded PowerShell, beacon `networkfilter`) hiện **không có trong dữ liệu đã tải** — chúng nằm ở sourcetype (Sysmon full) chưa nạp. Việc quét chuỗi con từng báo sai đã được đính chính: `4656` bị nhầm là `4625` (do RecordNumber chứa "4625"), `iexplore.exe` bị nhầm là `IEX`. Tức là **0× failed-logon 4625 thật, 0× encoded-PS thật, 0× beacon `networkfilter` thật** trong dữ liệu hiện có.

2. **Judge LLM non-deterministic.** Cùng bằng chứng cho các độ tự tin khác nhau qua các lần chạy (đã ghi 0.82 / 0.85 / 0.87 / 0.88, và các bản cũ tới 0.92 / 0.97). Judge chỉ là advisory; verdict chính luôn là rules tất định.

3. **F1 chưa đo.** Precision/recall/F1 của claim, cạnh và câu trả lời chưa được đo trên bộ có nhãn đầy đủ. Không có con số F1 tổng quát nào trong báo cáo này. Chi phí USD là ước lượng từ bảng giá cục bộ và số token, không phải hóa đơn.

4. **Hai backend, một dataset.** Chỉ SQLite (CDB) và Splunk. EDR/IDS/thư chỉ thành nguồn khi có adapter và kiểm thử năng lực tương ứng. Khái quát từ BOTS v1 sang mọi SIEM chưa được tài liệu kiến trúc cho phép.

5. **Baseline window ngắn.** Demo baseline chạy trên một ngày; PEAK khuyến nghị cửa sổ 30–90 ngày cho hầu hết nguồn.

6. **`VALIDATED` chỉ là parser chấp nhận cú pháp.** SPL đạt trạng thái `VALIDATED` nghĩa là parser Splunk chấp nhận cú pháp đọc-only, không phải một detection đã phát hành với tỉ lệ dương tính giả đã đo.

7. **Cổng SPL chỉ nhận một tập con SPL.** `NativeQueryGate` cố ý không parse toàn bộ SPL; an toàn với tập con đó không phải an toàn với mọi SPL Splunk.

8. **Hai thế hệ mã cùng tồn tại.** Đường v7 (`SemanticGoalGraph`) và đường tương thích cũ (discovery/adaptive, ClaimGraph) cùng nằm trong `execute_hunt`. Checklist còn mục gỡ ngôn ngữ template và các nhánh từ khóa còn sót; đọc một hàm đời cũ mà tưởng nó là cửa duy nhất của mọi câu hỏi sẽ hiểu sai hệ thống.

## 8.3. Đe dọa tới tính hợp lệ (threats to validity)

- **Tính hợp lệ nội tại:** đánh giá độ đặc hiệu dùng định nghĩa "benign = toàn bộ eval DB", trong đó gần như không có các chặng mà PoC dựng sẵn nhắm tới. Do đó 0 FP là kết quả đúng nhưng cần đọc kèm ngữ cảnh: nó đo tính "không báo bừa trên nhiễu", không phải "không bỏ sót tấn công".
- **Tính hợp lệ ngoại tại:** kết quả trên CDB (SQLite) chưa khái quát sang Splunk sản xuất; một lần chạy lại chỉ chứng minh đúng hành vi đã đo của lần đó.
- **Tính hợp lệ cấu trúc:** judge non-deterministic khiến bất kỳ chỉ số nào dựa trên judge đều phải đọc như advisory, không như số đo cứng.

## 8.4. So sánh với kỳ vọng ban đầu

Ba lỗi cố hữu (L1–L3, Chương 1) được chặn ở cả tầng thiết kế lẫn tầng hành vi đo được:

| Lỗi | Cơ chế chặn (thiết kế) | Bằng chứng hành vi (đo) |
|---|---|---|
| L1 — mô hình viết thẳng truy vấn | Lớp ngữ nghĩa có kiểu + `NativeQueryGate` | Test biên dịch từ chối SPL; verdict do rules |
| L2 — thiên kiến kịch bản theo từ khóa | Phân nhánh theo tham số; batch không Top-K | `test_counterfactual_matrix.py`; nguồn chọn theo hợp đồng kiểu |
| L3 — đọc rỗng thành lành tính | Ba trạng thái tuyến + âm tính phải cấp phép | 3 PoC âm tính → NO_SIGNAL, 0 token (mục 7.4) |
