# Chương 9. Kết luận và hướng phát triển

## 9.1. Kết luận

Đồ án đã tái cấu trúc một kho mã săn mối đe dọa cỡ lớn thành một hệ thống nhỏ gọn, tích hợp PEAK Assistant của Cisco Talos cho pha Prepare, giữ pha Execute tất định trên telemetry, và bổ sung pha Act dưới dạng khuyến nghị có xếp hạng để người săn quyết định. Các mục tiêu đề ra ở mục 1.3 được đánh giá như sau.

- **Làm gọn kho:** mã nguồn giảm từ khoảng 36.400 xuống khoảng 9.400 dòng (gồm khoảng 2.300 dòng của luồng Prepare-only), số tệp kiểm thử từ khoảng 80 xuống 9 (146 bài, đều đạt; adapter Splunk khoảng 2.300 dòng cùng tám bài kiểm thử Splunk thật đã gỡ khỏi nhánh chính, còn ở commit `4dace56`), bảo toàn khả năng khôi phục qua thẻ `v6-engine-final`.
- **Tích hợp PEAK Assistant:** cầu nối `prepare.py` gọi `able_table` và `plan_hunt`, chạy thành công trên cả bốn PoC với hai cấu hình LLM khác nhau, có gọi lại có backoff và quay về chế độ không LLM khi lỗi.
- **Khuyến nghị hỗ trợ quyết định:** năm loại khuyến nghị, độ tin cậy, lý do, giới hạn, lựa chọn xếp hạng, câu hỏi và rủi ro; mọi khuyến nghị có `decision_required = true`.
- **LLM tuỳ chọn:** hệ thống chạy trọn vẹn với `--offline` hoặc khi `.env` chưa điền, có kiểm thử riêng, và có thể chọn mô hình miễn phí qua `--model`; một mô hình miễn phí (`nvidia/nemotron-3-super-120b-a12b:free`) đã chạy hết bốn PoC cho cùng khuyến nghị như mô hình trả phí.
- **Thực nghiệm trung thực:** PoC Joomla có 200 bản ghi hiển thị (mỗi bước có ít nhất khoảng 2.000 hàng khớp) và khuyến nghị chuyển IR ở mức tin cậy trung bình, với lý do rõ ràng; ba PoC còn lại cho kết quả rỗng và được đóng kèm cảnh báo, không bị gọi là "sạch". Mười lỗi phát hiện khi chạy thật và khi rà soát cuối đều được ghi lại cùng cách xử lý.
- **Luồng Prepare-only:** từ PoC công khai (NVD, GitHub) sinh `HuntPlan` có schema, mọi truy vấn do LLM viết bị duyệt tĩnh trước khi rời dự án (kể cả quy tắc lọc theo tiến trình cha cho truy vấn hậu khai thác), chữ lẫn ngôn ngữ khác bị yêu cầu viết lại, và `verify` tất định nhận kết quả của đội thực thi để chấp nhận hoặc sinh vòng pivot. Thử trên Log4Shell và Spring4Shell bằng mô hình miễn phí; mục 7.10 nêu số liệu và giới hạn.
- **Tài liệu:** hướng dẫn thực hành từ cài đặt đến viết PoC (Chương 6), tài liệu kiến trúc và định dạng PoC trong thư mục `docs/`.

Đóng góp có tính khái quát hơn là một mẫu kiến trúc: **dùng LLM ở hai đầu của một lõi tất định, ghi rõ ranh giới tin cậy, và trình bày kết quả rỗng như một khẳng định có điều kiện**. Mẫu này không riêng cho săn mối đe dọa; nó áp dụng được cho bất kỳ quy trình nào mà LLM hỗ trợ con người ra quyết định trên dữ liệu.

## 9.2. Hạn chế còn lại

Tóm tắt những điều chưa làm hoặc chưa kiểm chứng (chi tiết ở các mục 7.9 và 8.3): chưa chạy trên Splunk thật (kể cả các thay đổi truy xuất mới và mọi truy vấn của kế hoạch Prepare-only); vòng `verify` chưa nhận kết quả thật của một đội thực thi; chưa thử tác tử nghiên cứu `--research`; độ phủ mới liệt kê loại sự kiện chứ chưa tự đối chiếu với predicate; phạm vi host vẫn suy ra từ văn xuôi bằng heuristic; số khớp khi quét chạm trần chỉ là cận dưới; chi phí token của PEAK chưa đo; recall chỉ đo được một pha tấn công; judge chưa được hiệu chỉnh trên dữ liệu có nhãn.

## 9.3. Hướng phát triển

Các hướng được sắp theo mức độ cấp thiết, từ sửa các thiếu sót đã biết đến mở rộng.

**Ngắn hạn (sửa thiếu sót).**
1. Đếm số khớp thật bằng truy vấn `COUNT` riêng thay vì cận dưới khi lượt quét chạm giới hạn 2.000 hàng.
2. Tách trường `host_scope` tường minh trong PoC thay vì đọc tên máy từ `able.location` bằng heuristic, và đưa bộ lọc host vào bản nháp SPL.
3. Đối chiếu tự động theo loại sự kiện: PoC khai báo `native_type`/`event_id` cần có (ví dụ 4625), hệ thống so với cơ cấu loại sự kiện đã liệt kê và kết luận "thiếu dữ liệu" khi không có.
4. Chạy kiểm thử tích hợp với Splunk trong một container; cài đặt độ phủ theo cửa sổ, theo host và theo loại sự kiện cho adapter Splunk; kiểm tra giới hạn quét 2.000 hàng và tham số `require_nonempty` ở đó.

**Trung hạn (nâng chất lượng).**
5. Chạy PoC trên nhiều cửa sổ (quét toàn bộ 28 ngày theo từng ngày) và báo tỷ lệ ngày có hit.
6. Biến thể vị từ có kiểm soát: một tập quy tắc viết lại (ví dụ `-enc` và `-EncodedCommand`) áp dụng tất định chứ không để LLM tự nới.
7. Mở rộng `--redact` sang chuỗi tự do (dòng lệnh, URL, tên miền) và sang văn bản gửi cho PEAK Prepare; thử với mô hình cục bộ trên dữ liệu thật.
8. Hiệu chỉnh ngưỡng judge trên một tập có nhãn: lấy các pha tấn công khác của BOTS v1 và v2, đo tỷ lệ judge trùng nhãn.
9. Làm giàu bằng ngữ cảnh tài sản (vai trò máy, tài khoản dịch vụ) để khuyến nghị không còn phải nhắc "xác nhận vai trò máy".

**Cho luồng Prepare-only.** Chạy kế hoạch trên một Splunk thật (có thể trong container) và đưa kết quả thật qua `verify`; nhờ chuyên gia chấm chất lượng truy vấn; để `verify` đọc đủ các hành động điểm dừng thay vì chỉ `escalate`; thêm đếm sự kiện thay cho đếm dòng; mở rộng sang PoC không có CVE (bài viết, quy tắc Sigma); mở rộng từ vựng và kiểm tra bộ phát hiện ngôn ngữ trên đầu ra thật nhiều hơn.

**Dài hạn (mở rộng phạm vi).**
10. Hỗ trợ hai loại săn còn lại của PEAK: baseline (dùng `describe_data` làm nền) và M-ATH.
11. Vòng phản hồi: kết quả quyết định của người săn (chấp nhận, bác bỏ khuyến nghị) được ghi lại và dùng để cải thiện luật và lời nhắc.
12. Tích hợp với hệ thống quản lý sự cố (ticket) để gói `ir/` được chuyển tự động sau khi người săn xác nhận.
13. Đánh giá với người dùng thật: nhờ các nhà phân tích săn mối đe dọa dùng hệ thống trên các giả thuyết của họ và đo mức hữu ích của khuyến nghị, một điều đồ án này chưa làm được.
