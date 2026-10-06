# Chương 9 — Kết luận và hướng phát triển

## 9.1. Kết luận

Báo cáo này trình bày AI Agent Hunting, một tác tử điều tra mối đe dọa bị ràng buộc bởi bằng chứng và vận hành theo khung PEAK của Splunk. Đóng góp trung tâm về mặt kiến trúc là một ranh giới nhận thức chặt: **mô hình ngôn ngữ chỉ đề xuất; census, probe, adapter, sổ cái append-only, bộ kiểm chứng quan hệ và bộ điều khiển tất định mới giữ quyền với sự thật, truy vấn và quyết định dừng.** Đơn vị lập luận là một đồ thị mục tiêu có kiểu, gắn vào năng lực nhà cung cấp đã kiểm, rồi đối chiếu với quan sát có trích dẫn.

Hệ thống đáng tin ở chỗ nó từ chối hai phép biến đổi nguy hiểm: biến một câu tiếng người thành một câu chuyện tấn công (chặn thiên kiến kịch bản), và biến một truy vấn rỗng thành một kết luận âm (phân biệt "không có bằng chứng" với "có bằng chứng về sự vắng mặt").

Đóng góp mới nhất của phiên bản — **cổng PEAK Prepare bắt buộc trên mọi đường săn** — khép lại một khoảng cách giữa tuyên bố "bám PEAK" và hiện thực: nay không đường săn nào (giả thuyết, baseline, M-ATH) chạy mà thiếu một Prepare plan, dù là plan tường minh hay plan suy tự động được in ra để audit.

Về mặt thực nghiệm, trên bộ dữ liệu công khai BOTS v1, hệ thống đạt:

- **514 test đạt / 13 bỏ qua / 0 thất bại** — tính đúng đắn phần mềm sau khi tích hợp cổng mới.
- **0 dương tính giả trên 4.38 triệu dòng lành tính** — độ đặc hiệu 100% trong phạm vi đo.
- **Một dương tính thật đầu tiên** trên tấn công Joomla RCE (MATCHED, 199 quan sát, judge TRUE_POSITIVE).

Những kết quả này cho thấy hệ thống phát hiện được tấn công thật mà không báo bừa trên nhiễu lành tính, trong phạm vi dữ liệu đã đo. Đồng thời, báo cáo giữ trung thực về những gì chưa đo được: recall mới đo một chặng, F1 tổng quát chưa có do thiếu nhãn.

## 9.2. Hướng phát triển

Theo thứ tự ưu tiên, bám các mục còn mở trong `04-IMPLEMENTATION-CHECKLIST.md`:

1. **Thêm sourcetype để đo các chặng còn lại.** Nạp Sysmon full và các nguồn còn thiếu để đo recall trên failed-logon (4625), encoded PowerShell, và beacon C2 — hiện các chặng này không có trong dữ liệu đã tải.
2. **Đo F1 trên dữ liệu có nhãn.** Xây bộ nhãn cho claim, cạnh và câu trả lời để đo precision/recall/F1 thay vì chỉ đo độ đặc hiệu và recall bước match.
3. **Hoàn tất cổng sản xuất Splunk.** Đưa `SplunkLiveAdapter` qua các cổng bằng chứng đầy đủ để một kết quả trên Splunk sống có cùng mức tin như trên CDB.
4. **Khép các đường tương thích cũ.** Gỡ ngôn ngữ template và các nhánh từ khóa còn sót, để đường v7 (`SemanticGoalGraph`) là cửa duy nhất cho mọi câu hỏi.
5. **Mở rộng nhà cung cấp.** Thêm adapter EDR/IDS/thư với census, probe, control và bộ kiểm năng lực — executor và verifier không nhận thêm nhánh theo tên hãng.
6. **Siết PEAK Prepare sâu hơn (tùy chọn).** Ví dụ bắt buộc `research_refs` do người dùng cung cấp thay vì cho suy mặc định, hoặc ghi plan đã-suy vào artifact của hunt để lưu vết đầy đủ.

## 9.3. Lời kết

Cho đến khi các mục trên hoàn tất, một lần săn thành công trong hệ thống này là **một tài khoản có trích dẫn hoặc một kết quả không kết luận có lý do** — không phải một đoạn văn trông hợp lý. Đó là tiêu chí thành công mà một tác tử điều tra an ninh nên hướng tới: đúng đắn về bằng chứng quan trọng hơn trôi chảy về ngôn từ.
