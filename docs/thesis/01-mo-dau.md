# Chương 1. Mở đầu

## 1.1. Đặt vấn đề

Các hệ thống phát hiện xâm nhập dựa trên luật và chữ ký chỉ bắt được những gì đã được mô tả trước. Kẻ tấn công có kỹ năng thường đi vòng qua các luật đó bằng công cụ hợp pháp có sẵn trên hệ thống, bằng mã hoá lệnh, hoặc bằng hành vi trông giống quản trị thông thường. Săn mối đe dọa (threat hunting) bổ sung cho phát hiện tự động bằng cách đặt một giả thuyết về hoạt động của kẻ tấn công rồi chủ động dùng dữ liệu để xác nhận hoặc bác bỏ giả thuyết đó. Hoạt động này phụ thuộc nhiều vào kinh nghiệm của người săn và tốn thời gian ở giai đoạn chuẩn bị: đọc tài liệu về kỹ thuật tấn công, viết giả thuyết kiểm chứng được, xác định nguồn dữ liệu cần dùng, rồi dịch tất cả thành các truy vấn cụ thể.

Khung PEAK (Prepare, Execute, Act with Knowledge) của Splunk SURGe mô tả quy trình đó một cách có cấu trúc [1]. Giai đoạn Prepare của PEAK, gồm chọn chủ đề, nghiên cứu, phát biểu giả thuyết, lập bảng ABLE (Actor, Behavior, Location, Evidence), xác định phạm vi và lập kế hoạch, là phần mà các mô hình ngôn ngữ lớn (LLM) có thể hỗ trợ tốt vì nó chủ yếu là đọc, tổng hợp và viết. Cisco Talos đã công bố mã nguồn mở **PEAK Assistant** [5], một tập tác tử LLM thực hiện đúng các việc đó và xuất ra báo cáo nghiên cứu, bảng ABLE và kế hoạch săn. Chính nhóm tác giả cũng nói rõ đây là bản chứng minh khái niệm, chưa qua kiểm thử bảo mật, nên chỉ phù hợp chạy cục bộ.

Việc dùng LLM trong săn mối đe dọa đặt ra một vấn đề niềm tin. LLM có thể viết ra những khẳng định nghe hợp lý nhưng không có căn cứ trong dữ liệu [12]. Nếu để LLM vừa lập kế hoạch vừa kết luận, người săn khó phân biệt đâu là điều dữ liệu chứng minh, đâu là điều mô hình suy đoán. Một vấn đề thứ hai tinh tế hơn: khi truy vấn không trả về gì, người dùng và cả mô hình đều dễ diễn giải là "không có tấn công", trong khi nguyên nhân có thể là dữ liệu không được thu thập, cửa sổ thời gian quá hẹp, hoặc vị từ viết sai. Nguyên tắc "không có bằng chứng không đồng nghĩa với bằng chứng không có" [13] vì vậy cần được hiện thực thành quy tắc của hệ thống chứ không chỉ là lời nhắc.

## 1.2. Bối cảnh và động cơ thực hiện

Kho mã `AI_Agent_Hunting` ban đầu (phiên bản v6) là một engine điều tra tổng quát xây quanh ba đồ thị: đồ thị khẳng định (ClaimGraph), đồ thị năng lực nhà cung cấp (CapabilityGraph) và đồ thị bằng chứng (EvidenceGraph). Engine có hơn ba mươi sáu nghìn dòng mã nguồn, hàng chục mô-đun và khoảng tám mươi tệp kiểm thử, giải bài toán trả lời câu hỏi điều tra tự do. Qua thực tế sử dụng, phần có giá trị nhất của kho lại là đường chạy PoC: nhận một giả thuyết đã cụ thể hoá, chạy các vị từ trên telemetry, rồi báo cáo. Phần engine lớn gây ba khó khăn: khó đọc và khó bảo trì, khó giải thích cho người dùng cuối, và trùng lặp với phần Prepare mà PEAK Assistant đã làm tốt hơn.

Động cơ của đồ án là tái cấu trúc kho theo hướng: (i) giữ phần thực thi tất định đã được kiểm chứng; (ii) thay phần chuẩn bị tự xây bằng PEAK Assistant; (iii) bổ sung phần còn thiếu nhất là đầu ra có ích cho con người, tức một khuyến nghị có lý do để người săn ra quyết định; (iv) làm gọn kho để người mới đọc được trong vài giờ.

## 1.3. Mục tiêu nghiên cứu

Mục tiêu tổng quát là xây dựng một trợ lý săn mối đe dọa dùng PEAK Assistant cho pha Prepare, thực thi tất định cho pha Execute, và đưa ra khuyến nghị hỗ trợ quyết định cho pha Act, kiểm chứng trên dữ liệu thật.

Các mục tiêu cụ thể:

- Phân tích và làm gọn kho mã v6, giữ lại đường chạy PoC cùng các adapter telemetry.
- Tích hợp PEAK Assistant qua một lớp cầu nối có khả năng chịu lỗi, dùng chung một cấu hình LLM.
- Thiết kế bộ luật khuyến nghị tất định, có giải thích, không để LLM thay đổi sự thật về bằng chứng.
- Bảo đảm LLM là tuỳ chọn: không cấu hình LLM thì hệ thống vẫn chạy.
- Chạy bốn PoC có sẵn trên bộ dữ liệu Boss of the SOC v1, ghi nhận kết quả, lỗi và hạn chế một cách trung thực.
- Viết tài liệu hướng dẫn thực hành đủ để một người mới cài đặt, chạy, đọc kết quả và tự viết PoC.

## 1.4. Đối tượng và phạm vi

Đối tượng nghiên cứu là quy trình săn theo giả thuyết (hypothesis-driven hunting) của PEAK, trong đó giả thuyết đã được cụ thể hoá thành PoC. Phạm vi gồm:

- **Trong phạm vi:** pha Prepare qua PEAK Assistant (ABLE, kế hoạch săn); pha Execute trên hai loại telemetry là cơ sở dữ liệu SQLite (CDB) và Splunk; pha Act dạng khuyến nghị, bản nháp truy vấn SPL, backlog và ghi chú cho các bên liên quan; kiểm chứng trên Boss of the SOC v1.
- **Ngoài phạm vi:** săn theo đường cơ sở (baseline) và săn có hỗ trợ mô hình học máy (M-ATH) của PEAK; huấn luyện mô hình; tự động hoá hành động phản ứng sự cố; đánh giá định lượng độ chính xác trên nhiều bộ dữ liệu.
- **Giới hạn đã biết:** bộ dữ liệu có nhãn tấn công hạn chế; adapter Splunk và bản nháp SPL chưa được chạy trên một máy chủ Splunk thật trong đồ án này.

## 1.5. Phương pháp nghiên cứu

Đồ án theo hướng nghiên cứu thiết kế và thực nghiệm. Về lý thuyết, tổng hợp tài liệu về săn mối đe dọa, khung PEAK, MITRE ATT&CK, hệ thống đa tác tử dùng LLM và độ tin cậy của LLM. Về thiết kế, xác lập yêu cầu, chọn kiến trúc, và đặt ra các bất biến mà mọi thành phần phải tôn trọng. Về hiện thực, viết mã Python, kiểm thử đơn vị, và tích hợp thư viện PEAK Assistant ở một phiên bản được ghim theo mã băm commit. Về thực nghiệm, chạy hệ thống trên dữ liệu thật, thu thập đầu ra, phân tích từng kết quả và ghi lại mọi lỗi phát sinh. Mọi số liệu trong luận văn lấy từ kết quả chạy lưu trong thư mục `results/` của kho.

## 1.6. Đóng góp chính

1. Một kiến trúc ghép PEAK Assistant (không tất định) với bộ thực thi tất định, trong đó ranh giới tin cậy được ghi rõ và được kiểm thử.
2. Bộ luật khuyến nghị có giải thích, xử lý riêng bốn trường hợp dễ nhầm: chuỗi khớp một phần, kết quả khớp nhưng chưa chứng minh thành công, kết quả rỗng do thiếu dữ liệu, và kết quả rỗng do phạm vi tìm kiếm (host) không có dữ liệu.
3. Cơ chế vận hành LLM thực tế: gọi lại có backoff, quay về chế độ không LLM khi lỗi, chấp nhận nhiều dạng đầu ra JSON, và chế độ hoàn toàn không cần LLM.
4. Làm gọn kho từ khoảng 36.400 dòng xuống khoảng 9.200 dòng mã nguồn mà vẫn giữ khả năng khôi phục engine cũ.
5. Bộ kết quả thực nghiệm và hướng dẫn thực hành có thể tái chạy.

## 1.7. Bố cục luận văn

Chương 2 trình bày cơ sở lý thuyết. Chương 3 phân tích bài toán và yêu cầu. Chương 4 mô tả thiết kế kiến trúc và bộ luật khuyến nghị. Chương 5 mô tả cài đặt. Chương 6 là hướng dẫn thực hành. Chương 7 trình bày thực nghiệm và đánh giá. Chương 8 thảo luận hạn chế. Chương 9 kết luận và đề xuất hướng phát triển. Phần phụ lục cung cấp tệp PoC mẫu, báo cáo mẫu, tham chiếu dòng lệnh, cấu hình, danh sách kiểm thử và bảng thuật ngữ.
