# Chương 9. Kết luận và hướng phát triển

## 9.1. Kết luận

Đồ án đã tái cấu trúc một kho mã săn mối đe dọa cỡ lớn thành một hệ thống nhỏ gọn, tích hợp PEAK Assistant của Cisco Talos cho pha Prepare, giữ pha Execute tất định trên telemetry, và bổ sung pha Act dưới dạng khuyến nghị có xếp hạng để người săn quyết định. Các mục tiêu đề ra ở mục 1.3 được đánh giá như sau.

- **Làm gọn kho:** mã nguồn giảm từ khoảng 36.400 xuống khoảng 8.400 dòng, số tệp kiểm thử từ khoảng 80 xuống 6 (86 bài kiểm thử, 78 đạt và 8 bỏ qua vì cần Splunk), bảo toàn khả năng khôi phục qua thẻ `v6-engine-final`.
- **Tích hợp PEAK Assistant:** cầu nối `prepare.py` gọi `able_table` và `plan_hunt`, chạy thành công trên cả bốn PoC với hai cấu hình LLM khác nhau, có gọi lại có backoff và quay về chế độ không LLM khi lỗi.
- **Khuyến nghị hỗ trợ quyết định:** năm loại khuyến nghị, độ tin cậy, lý do, giới hạn, lựa chọn xếp hạng, câu hỏi và rủi ro; mọi khuyến nghị có `decision_required = true`.
- **LLM tuỳ chọn:** hệ thống chạy trọn vẹn với `--offline` hoặc khi `.env` chưa điền, có kiểm thử riêng, và có thể chọn mô hình miễn phí qua `--model`; một mô hình miễn phí (`nvidia/nemotron-3-super-120b-a12b:free`) đã chạy hết bốn PoC cho cùng khuyến nghị như mô hình trả phí.
- **Thực nghiệm trung thực:** PoC Joomla có 199 bản ghi và khuyến nghị chuyển IR ở mức tin cậy trung bình, với lý do rõ ràng; ba PoC còn lại cho kết quả rỗng và được đóng kèm cảnh báo, không bị gọi là "sạch". Bảy lỗi phát hiện khi chạy thật đều được ghi lại cùng cách xử lý.
- **Tài liệu:** hướng dẫn thực hành từ cài đặt đến viết PoC (Chương 6), tài liệu kiến trúc và định dạng PoC trong thư mục `docs/`.

Đóng góp có tính khái quát hơn là một mẫu kiến trúc: **dùng LLM ở hai đầu của một lõi tất định, ghi rõ ranh giới tin cậy, và trình bày kết quả rỗng như một khẳng định có điều kiện**. Mẫu này không riêng cho săn mối đe dọa; nó áp dụng được cho bất kỳ quy trình nào mà LLM hỗ trợ con người ra quyết định trên dữ liệu.

## 9.2. Hạn chế còn lại

Tóm tắt những điều chưa làm hoặc chưa kiểm chứng (chi tiết ở các mục 7.9 và 8.3): chưa chạy trên Splunk thật; chưa thử tác tử nghiên cứu `--research`; độ phủ mới theo nhóm nguồn chứ chưa theo loại sự kiện; giới hạn 100 hàng mỗi bước chưa được báo trong báo cáo; chi phí token của PEAK chưa đo; recall chỉ đo được một pha tấn công; judge chưa được hiệu chỉnh trên dữ liệu có nhãn.

## 9.3. Hướng phát triển

Các hướng được sắp theo mức độ cấp thiết, từ sửa các thiếu sót đã biết đến mở rộng.

**Ngắn hạn (sửa thiếu sót).**
1. Báo cáo rõ khi bước chạm giới hạn 100 hàng, kèm số bản ghi đếm thật bằng truy vấn `COUNT`.
2. Dùng cửa sổ của PoC trong bản nháp SPL thay vì `earliest=-14d` cố định.
3. Độ phủ theo loại sự kiện: PoC khai báo `native_type`/`event_id` cần có, và hệ thống kiểm tra từng loại trong cửa sổ trước khi nói "đóng".
4. Chạy kiểm thử tích hợp với Splunk trong một container và cài đặt `source_presence` cho adapter Splunk.

**Trung hạn (nâng chất lượng).**
5. Chạy PoC trên nhiều cửa sổ (quét toàn bộ 28 ngày theo từng ngày) và báo tỷ lệ ngày có hit.
6. Biến thể vị từ có kiểm soát: một tập quy tắc viết lại (ví dụ `-enc` và `-EncodedCommand`) áp dụng tất định chứ không để LLM tự nới.
7. Đo token của PEAK bằng proxy HTTP hoặc bằng cách bọc ứng dụng khách mô hình; báo cáo chi phí đầy đủ.
8. Hiệu chỉnh ngưỡng judge trên một tập có nhãn: lấy các pha tấn công khác của BOTS v1 và v2, đo tỷ lệ judge trùng nhãn.
9. Làm giàu bằng ngữ cảnh tài sản (vai trò máy, tài khoản dịch vụ) để khuyến nghị không còn phải nhắc "xác nhận vai trò máy".

**Dài hạn (mở rộng phạm vi).**
10. Hỗ trợ hai loại săn còn lại của PEAK: baseline (dùng `describe_data` làm nền) và M-ATH.
11. Vòng phản hồi: kết quả quyết định của người săn (chấp nhận, bác bỏ khuyến nghị) được ghi lại và dùng để cải thiện luật và lời nhắc.
12. Tích hợp với hệ thống quản lý sự cố (ticket) để gói `ir/` được chuyển tự động sau khi người săn xác nhận.
13. Đánh giá với người dùng thật: nhờ các nhà phân tích săn mối đe dọa dùng hệ thống trên các giả thuyết của họ và đo mức hữu ích của khuyến nghị, một điều đồ án này chưa làm được.
