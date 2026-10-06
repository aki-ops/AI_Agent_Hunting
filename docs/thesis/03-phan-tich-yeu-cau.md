# Chương 3. Phân tích bài toán và yêu cầu hệ thống

## 3.1. Hiện trạng kho mã v6

Trước khi tái cấu trúc, kho `AI_Agent_Hunting` có hai đường chạy độc lập. Đường thứ nhất là engine giả thuyết tự do: người dùng gõ một câu hỏi hoặc một mã CVE/TTP, một LLM biên dịch thành đồ thị khẳng định, engine chọn nhà cung cấp dữ liệu qua đồ thị năng lực, thực thi truy vấn, xác minh quan hệ và dựng đồ thị bằng chứng. Đường thứ hai là đường PoC: người dùng viết một PoC dạng JSON gồm vài vị từ cụ thể, tác tử PoC chạy từng vị từ qua adapter, rồi một bước judge tuỳ chọn đánh giá kết quả.

Kiểm kê cho thấy các điểm sau:

- Tổng mã nguồn `src/` khoảng 36.400 dòng; riêng tệp `engine.py` hơn 3.300 dòng, `cli.py` hơn 1.700 dòng.
- Đường PoC chỉ phụ thuộc vào khoảng 7.200 dòng (gồm hai adapter, các hợp đồng dữ liệu mà adapter cần, và mô-đun Act). Phần còn lại phục vụ riêng engine giả thuyết tự do.
- Phần "Prepare" của PEAK đã được tự xây (`peak.py`: cổng kiểm tra trường bắt buộc, trình hướng dẫn nhập, đọc kế hoạch YAML). Nó kiểm tra việc *có* điền đủ trường, nhưng không giúp người dùng *viết* ra nội dung tốt.
- Kết quả cuối của đường PoC là một nhãn (MATCHED/EMPTY) kèm một nhận định judge. Người săn phải tự suy ra nên làm gì tiếp.

## 3.2. Vấn đề cần giải quyết

Từ hiện trạng, đồ án tập trung vào bốn vấn đề.

**Vấn đề 1: độ phức tạp vượt nhu cầu.** Phần lớn người dùng cần chạy một giả thuyết đã cụ thể hoá và nhận kết quả dễ hiểu, không cần một engine suy diễn tổng quát. Độ phức tạp thừa làm tăng chi phí bảo trì và rào cản học.

**Vấn đề 2: chuẩn bị săn đang là việc thủ công.** Viết bảng ABLE, xác định nguồn dữ liệu và lập kế hoạch cần đọc tài liệu và viết nhiều văn bản. PEAK Assistant tự động hoá chính các việc này, nên việc tiếp tục tự xây là lãng phí.

**Vấn đề 3: đầu ra chưa phục vụ quyết định.** "MATCHED, 200 bản ghi" chưa cho người săn biết có nên chuyển cho IR hay không, độ tin cậy ra sao, và còn thiếu gì. Một cuộc săn rỗng còn tệ hơn: nhãn "EMPTY" dễ bị đọc nhầm thành "an toàn".

**Vấn đề 4: ràng buộc vận hành LLM.** Endpoint LLM có thể không sẵn sàng, bị giới hạn tốc độ, trả lỗi thoáng qua hoặc tốn phí. Người dùng có thể chưa có khoá API. Hệ thống không được sập hay trả kết quả sai trong những tình huống đó.

## 3.3. Yêu cầu chức năng

Bảng: Yêu cầu chức năng
| Mã | Yêu cầu | Căn cứ |
|---|---|---|
| FR1 | Nạp PoC từ tệp JSON, kiểm tra các trường Prepare bắt buộc | Vấn đề 2 |
| FR2 | Gọi PEAK Assistant sinh bảng ABLE và kế hoạch săn cho mỗi PoC | Vấn đề 2 |
| FR3 | Thực thi các vị từ literal trên telemetry qua adapter (CDB, Splunk) | Giữ giá trị đường PoC |
| FR4 | Kiểm tra độ phủ của từng nguồn dữ liệu trong cửa sổ thời gian | Vấn đề 3 |
| FR5 | Sinh khuyến nghị xếp hạng với lý do, giới hạn, câu hỏi, rủi ro | Vấn đề 3 |
| FR6 | Chạy được nhiều PoC một lần và tổng hợp bảng kết quả | Vấn đề 1 |
| FR7 | Xuất báo cáo Markdown và JSON, bản nháp SPL, backlog | Pha Act của PEAK |
| FR8 | Chạy được hoàn toàn không có LLM | Vấn đề 4 |
| FR9 | Chọn được mô hình LLM từ dòng lệnh | Vấn đề 4 |

## 3.4. Yêu cầu phi chức năng

Bảng: Yêu cầu phi chức năng
| Mã | Yêu cầu | Cách kiểm chứng |
|---|---|---|
| NFR1 | LLM không tạo hoặc sửa bản ghi bằng chứng | Mọi hàng đều đến từ adapter; có kiểm thử |
| NFR2 | Kết quả phần tất định tái lập được | Cùng PoC và cùng dữ liệu cho cùng số bản ghi |
| NFR3 | Lỗi LLM không làm sập pipeline | Kiểm thử mô phỏng lỗi; chạy thật gặp lỗi 404 |
| NFR4 | Không ghi khoá API ra đĩa hay báo cáo | Cấu hình PEAK chỉ chứa `${ENV}`; quét kết quả không thấy khoá |
| NFR5 | Hệ thống nhỏ, đọc được | Mã nguồn dưới 10.000 dòng |
| NFR6 | Khôi phục được engine cũ | Gắn thẻ git `v6-engine-final` |
| NFR7 | Python 3.12 trở lên | Yêu cầu của PEAK Assistant |

## 3.5. Các phương án thiết kế

Ba phương án được cân nhắc cho việc dùng PEAK Assistant.

**Phương án A: dùng PEAK Assistant nguyên bản qua giao diện Streamlit.** Ưu điểm là không viết mã. Nhược điểm: hoàn toàn thủ công, không chạy được hàng loạt, không có bước thực thi trên telemetry của kho, không có khuyến nghị cuối. Phương án này chỉ cho phần Prepare.

**Phương án B: gọi PEAK Assistant qua máy chủ MCP của nó (`peak-mcp`).** Hợp với việc để một tác tử LLM khác điều phối. Nhược điểm: thêm một tầng giao thức và một tiến trình máy chủ, khó kiểm thử và khó chịu lỗi; điều phối bởi LLM đi ngược với yêu cầu phần Execute tất định.

**Phương án C (được chọn): dùng PEAK Assistant như thư viện Python.** Các hàm `able_table`, `plan_hunt` (và tuỳ chọn `researcher`) là hàm bất đồng bộ nhận chuỗi và trả chuỗi, nên đóng gói thành một lớp cầu nối mỏng trong tiến trình của hệ thống. Ưu điểm: tích hợp chặt, dễ chịu lỗi, dễ kiểm thử bằng cách giả lập lớp cầu nối. Nhược điểm: phụ thuộc vào API nội bộ của một dự án chứng minh khái niệm, nên cần ghim phiên bản theo mã băm commit (`dfabbb0`).

Bảng: So sánh các phương án tích hợp
| Tiêu chí | A: Streamlit | B: MCP | C: thư viện |
|---|---|---|---|
| Chạy hàng loạt | Không | Có | Có |
| Thực thi tất định tách khỏi LLM | Không áp dụng | Khó | Dễ |
| Kiểm thử tự động | Khó | Khó | Dễ |
| Độ phức tạp thêm | Thấp | Cao | Trung bình |
| Rủi ro thay đổi API | Thấp | Trung bình | Cao (giảm bằng ghim phiên bản) |

## 3.6. Các bất biến thiết kế

Từ vấn đề và yêu cầu, năm bất biến được đặt ra và áp dụng cho mọi thành phần mới.

1. **LLM không tạo bằng chứng.** Mọi bản ghi bằng chứng đến từ adapter. Văn bản của LLM chỉ xuất hiện ở các mục được gắn nhãn tham khảo.
2. **Khớp là literal và tái lập.** Cùng PoC, cùng dữ liệu cho cùng kết quả.
3. **Vắng dữ liệu không thành "sạch".** Nguồn có 0 bản ghi trong cửa sổ cho `COLLECT_DATA_THEN_RERUN`; kết quả rỗng khi nguồn có dữ liệu vẫn kèm cảnh báo về giới hạn.
4. **Người quyết định cuối cùng.** Mọi khuyến nghị có `decision_required = true`; hệ thống không thực hiện hành động phản ứng.
5. **LLM là tuỳ chọn.** Mọi chức năng cốt lõi chạy được khi không có LLM; LLM chỉ làm giàu thêm.
