# Chương 1 — Mở đầu

> Chương này đặt bối cảnh, phát biểu bài toán, nêu câu hỏi nghiên cứu, liệt kê đóng góp và khoanh vùng phạm vi. Các chương sau đi vào cơ sở lý thuyết (Chương 2), thiết kế (Chương 3–5), thực nghiệm (Chương 6), kết quả (Chương 7), và bàn luận/kết luận (Chương 8–9).

## 1.1. Bối cảnh

Săn mối đe dọa (threat hunting) là quy trình chủ động đi tìm những sự cố an ninh mà các cơ chế phát hiện tự động — luật (rule), chữ ký (signature), cảnh báo (alert) — đã bỏ sót. Khác với phòng thủ thụ động chờ cảnh báo bật lên, người săn mối đe dọa xuất phát từ một giả định: kẻ địch **có thể đã ở trong mạng**, và nhiệm vụ là tìm bằng chứng khẳng định hoặc bác bỏ giả định đó. Đặc trưng phương pháp luận quan trọng nhất của săn mối đe dọa là: một cuộc săn không tìm thấy gì vẫn có giá trị, miễn là nó ghi lại rõ đã tìm ở đâu và chưa tìm ở đâu — tức là phân biệt được "không có bằng chứng về tấn công" với "có bằng chứng về sự vắng mặt của tấn công".

Trong vài năm gần đây, mô hình ngôn ngữ lớn (LLM) được kỳ vọng tự động hóa săn mối đe dọa: đọc một câu hỏi tiếng người, sinh truy vấn cho SIEM, đọc kết quả, rồi kết luận. Kỳ vọng này hấp dẫn nhưng nguy hiểm, vì bản chất của LLM là sinh văn bản trôi chảy chứ không phải bảo đảm tính đúng đắn của bằng chứng. Một tác tử điều tra để LLM tự do dễ tạo ra kết luận nghe hợp lý nhưng không có cơ sở quan sát.

## 1.2. Phát biểu bài toán

Một nhà phân tích thường bắt đầu từ một trong các dạng đầu vào sau:

- Một câu hỏi tự do: *"Amber Turing đã vào một trang đối thủ. Tên miền đó là gì?"*
- Một giả thuyết: *"Máy chủ web này bị khai thác qua thành phần tìm kiếm Joomla."*
- Một định danh chuẩn: một mã CVE (`CVE-2024-21887`), một kỹ thuật MITRE ATT&CK (`T1059.001`), một chỉ báo xâm phạm (IOC).
- Một cảnh báo EDR chỉ có tên máy chủ và thời điểm.

Câu trả lời đúng phụ thuộc vào telemetry thật — Splunk, cơ sở SQLite kiểm thử, và về sau có thể là EDR hoặc thư điện tử. Ba khó khăn cốt lõi:

1. **Schema không thống nhất, và tên nguồn không phải nghĩa của dữ liệu.** Một nguồn được đặt tên "SMTP" nhưng thiếu trường người gửi và người nhận thì không phải là nguồn thư. Một tên máy chứa chuỗi `srv` không chứng minh đó là máy chủ.
2. **Truy vấn rỗng có nhiều nghĩa.** Rỗng có thể vì tấn công không xảy ra, hoặc vì nguồn không phủ, hoặc vì truy vấn bị cắt cụt, hoặc vì nhà cung cấp không tới được.
3. **Từ khóa dễ dẫn tới thiên kiến kịch bản.** Nếu hệ thống thấy chữ "email" rồi tự động chạy một kịch bản điều tra email, nó đã áp một câu chuyện lên dữ liệu thay vì để dữ liệu nói.

Từ đó, ba lỗi cố hữu mà hệ thống này được xây để **chặn bằng hợp đồng, không bằng lời nhắc**:

> **L1.** Mô hình ngôn ngữ viết thẳng truy vấn gốc (SPL/SQL/KQL) rồi tự tuyên bố kết quả.
>
> **L2.** Một từ khóa trong câu hỏi (`email`, `Tor`, `CVE`, `web`) chọn sẵn một kịch bản điều tra cố định.
>
> **L3.** Một truy vấn trả về rỗng và hoàn tất bị đọc thành "không có tấn công" (kết luận lành tính).

## 1.3. Câu hỏi nghiên cứu

- **CH1.** Có thể xây một tác tử săn mối đe dọa dùng LLM mà quyết định về sự thật, truy vấn và điểm dừng thuộc về logic tất định, còn LLM chỉ đóng vai đề xuất, hay không?
- **CH2.** Có thể ánh xạ một quy trình săn được ngành công nhận (PEAK của Splunk) lên một hệ thống phần mềm mà không đánh mất bản chất "PEAK là quy trình cho con người", đồng thời làm cho bước Prepare trở thành ràng buộc cứng, hay không?
- **CH3.** Trên dữ liệu tấn công thật, hệ thống có đạt độ đặc hiệu cao (ít dương tính giả) mà vẫn bắt được tấn công thật (có độ nhạy) hay không, và đo được đến đâu?

## 1.4. Đóng góp

Báo cáo này trình bày các đóng góp sau:

1. **Kiến trúc ba đồ thị có ranh giới nhận thức chặt** (Chương 4): tách `SemanticGoalGraph` (mục tiêu), `CapabilityGraph` (năng lực nguồn), `EvidenceGraph` (bằng chứng đã kiểm), với luật bất biến rằng chỉ bộ kiểm tất định mới nâng một cạnh từ "chưa chứng minh" lên "đã chứng minh".
2. **Hiện thực hóa bốn cửa của khung PEAK** (Chương 3): Prepare, Execute/Refine, Act, và M-ATH — trong đó M-ATH thay bước "train mô hình cục bộ" bằng gọi một mô hình pretrained bên ngoài, có cơ chế grounding.
3. **Cổng PEAK Prepare bắt buộc trên mọi đường săn** (Chương 5, đóng góp mới nhất của phiên bản này): trước đây Prepare chỉ bắt buộc trên đường PoC; nay nó là ràng buộc cứng cho cả đường giả thuyết, baseline và M-ATH, với cơ chế suy plan tự động và van thoát tường minh.
4. **Đánh giá thực nghiệm trên BOTS v1** (Chương 6–7): đo độ đặc hiệu trên 4.38 triệu dòng lành tính và độ nhạy trên tấn công Joomla thật, kèm phân tích trung thực về những gì chưa đo được.

## 1.5. Phạm vi và giới hạn phạm vi

**Trong phạm vi:** telemetry doanh nghiệp qua Splunk và một backend SQLite kiểm thử (gọi là CDB); các loại đầu vào giả thuyết/CVE/TTP/IOC/cảnh báo/PoC; đánh giá trên BOTS v1.

**Ngoài phạm vi hiện tại:** EDR, IDS, thư điện tử như nguồn thật (chỉ trở thành nguồn khi có adapter và kiểm thử năng lực tương ứng); chứng nhận PEAK chính thức của Splunk (kho hiện thực hóa quy trình, không nhận chứng nhận); và mọi tuyên bố khái quát ra "mọi SIEM" — một lần chạy lại chỉ chứng minh đúng hành vi đã đo của lần đó.

## 1.6. Cấu trúc báo cáo

Chương 2 trình bày cơ sở lý thuyết và công trình liên quan. Chương 3 mô tả khung PEAK và cách hệ thống hiện thực hóa. Chương 4 trình bày kiến trúc và mô hình nhận thức năm tầng. Chương 5 đặc tả đóng góp mới — cổng PEAK Prepare bắt buộc. Chương 6 mô tả phương pháp thực nghiệm (môi trường, dữ liệu, thiết kế test). Chương 7 báo cáo kết quả và tỉ lệ. Chương 8 bàn luận và nêu hạn chế. Chương 9 kết luận và nêu hướng phát triển. Cuối cùng là tài liệu tham khảo và phụ lục.
