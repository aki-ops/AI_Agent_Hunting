# Chương 2 — Cơ sở lý thuyết và công trình liên quan

> Chương này tách nguyên tắc được tài liệu bên ngoài nâng đỡ khỏi các lựa chọn kỹ thuật cục bộ. Mã định danh `REF-*` khớp bảng truy vết trong `03_LITERATURE-AND-TRACEABILITY.md`; đường dẫn đầy đủ ở Chương 10. Lưu ý phương pháp luận: "nâng đỡ" nghĩa là ủng hộ một *nguyên tắc*, không phải "chứng minh đúng một hiện thực cụ thể".

## 2.1. Định nghĩa và bản chất của săn mối đe dọa

Săn mối đe dọa là quá trình thủ công hoặc có máy hỗ trợ nhằm tìm những sự cố mà cơ chế phát hiện tự động bỏ sót. Điểm phân biệt với giám sát thụ động là **giả định vi phạm** (assume breach): người săn không chờ cảnh báo mà chủ động kiểm một giả thuyết về hoạt động của kẻ địch. Hệ quả phương pháp luận: kết quả của một cuộc săn không phải nhị phân "có/không tấn công", mà là một trong nhiều trạng thái — đã khẳng định, đã bác bỏ, không kết luận vì thiếu phủ, không kết luận vì thiếu năng lực nguồn, v.v. Hệ thống trong báo cáo này giữ đúng sự phân biệt đó thay vì ép một nhãn nhị phân (xem Chương 4, mô hình nhận thức).

## 2.2. Điều tra đa chặng và đồ thị nguồn gốc

Một nhánh nghiên cứu lâu năm dựng lại "đồ thị nguồn gốc" (provenance graph) từ nhật ký hệ thống để truy vết một cuộc xâm nhập qua tiến trình, tệp và kết nối mạng:

- **SLEUTH** [REF-SLEUTH] (Hossain và cộng sự, USENIX Security 2017) tái dựng kịch bản tấn công thời gian thực từ dữ liệu audit COTS bằng cách lan truyền nhãn nghi ngờ trên đồ thị phụ thuộc.
- **HOLMES** [REF-HOLMES] (Milajerdi và cộng sự, IEEE S&P 2019) phát hiện APT bằng cách tương quan các luồng thông tin đáng ngờ giữa các thực thể và ánh xạ chúng lên các bước của một chuỗi tấn công.
- **OmegaLog** [REF-OMEGALOG] (Hassan và cộng sự, NDSS 2020) hòa giải ngữ cảnh ứng dụng, hệ thống và mạng để một sự kiện giữ được độ trung thực khi đi qua nhiều tầng log.

**Điều các công trình này nâng đỡ:** giữ một *đồ thị bằng chứng có trích dẫn* thay vì một đoạn văn kết luận của mô hình. **Điều chúng không thiết lập:** rằng mọi câu hỏi phải đi qua một đồ thị tấn công cố định. Đây là căn cứ để hệ thống cho phép một câu hỏi tra cứu thuộc tính (ví dụ hỏi tên miền, hỏi phiên bản phần mềm) dừng ở một quan hệ đã chứng minh, mà không bắt buộc dựng một chuỗi tấn công đầy đủ.

## 2.3. Truy vấn logic có kiểu đứng trước cú pháp gốc

Việc để lớp ngữ nghĩa có kiểu đứng trước cú pháp truy vấn gốc có tiền lệ:

- **AIQL** [REF-AIQL] (Gao và cộng sự, USENIX ATC 2018) định nghĩa một ngôn ngữ truy vấn hành vi có kiểu trên dữ liệu giám sát hệ thống, rồi lập kế hoạch thực thi hiệu quả.
- **ThreatRaptor** [REF-THREATRAPTOR] (Gao và cộng sự, ICDE 2021) tách bước rút hành vi có cấu trúc từ báo cáo tình báo khỏi bước tổng hợp truy vấn.

Hệ thống này vay chính cấu trúc đó: `SemanticGoalGraph` và `QueryIntent` là lớp trung gian có kiểu; SPL và SQL chỉ được adapter biên dịch ra ở bước cuối. Điều này trực tiếp chặn lỗi **L1** (mô hình viết thẳng truy vấn gốc): mô hình không xuất SPL, nó xuất một đồ thị mục tiêu có kiểu, và một cổng AST tối thiểu (`NativeQueryGate`) mới quyết định một ứng viên SPL có được chạy hay không.

## 2.4. Vòng giả thuyết – bằng chứng – hành động, và sự không chắc chắn tường minh

- **Evidential Cyber Threat Hunting** [REF-ECTH] (tiền ấn phẩm arXiv:2104.10319) mô hình hóa tri thức, giả thuyết và hành động cùng độ không chắc chắn tường minh.
- **ATHAFI** [REF-ATHAFI] (arXiv:2003.03663) thu thập telemetry một cách thích nghi để kiểm giả thuyết.
- **TaHiTI** [REF-TAHITI] (FI-ISAC) là vòng đời săn theo giả thuyết mà giới ngân hàng dùng: chuẩn bị → săn → kết thúc bằng phát hiện hoặc bằng khoảng trống.
- **Maxam và cộng sự** [REF-USENIX-TH] (USENIX Security 2024) đo thực địa và cho thấy quy trình săn rất đa dạng — một workflow duy nhất áp cho mọi câu hỏi là một giả định yếu.

**Điều được nâng đỡ:** việc *gọi tên* sự không chắc chắn thay vì ép một nhãn âm tính. Đây là căn cứ để hệ thống giữ nhiều quyết định dừng tách biệt (đã giải, bị bác, không kết luận vì thiếu phủ/năng lực/không tới được nguồn/hết ngân sách) và trực tiếp chặn lỗi **L3** (đọc rỗng thành lành tính). Ngưỡng ngân sách cụ thể và tên enum là lựa chọn cục bộ, không do bài báo quy định.

## 2.5. Schema, năng lực và khớp schema bằng mô hình có kiểm sau

Nền tảng cho khái niệm `CapabilityGraph` (một thao tác nhà cung cấp khai báo kiểu đầu vào, kiểu sự thật đầu ra, phân vùng, quyền, phân trang, độ hoàn tất):

- **OCSF** [REF-OCSF] — lược đồ sự kiện trung lập nhà cung cấp, mở rộng được.
- **MITRE ATT&CK Data Components** [REF-MITRE-DC] và **Detection Strategies** [REF-MITRE-ANALYTICS] — tính chất quan sát được của từng kỹ thuật và chiến lược phát hiện mức cao.
- **OpenTelemetry** [REF-OTEL] — chuẩn hóa sự kiện và thuộc tính.
- **Microsoft Threat Hunting Assistant** [REF-MICROSOFT] — trợ lý truy vấn phải biết bảng và schema, và vẫn cần người duyệt.

Về khớp schema bằng mô hình ngôn ngữ có kiểm sau: **Schema Matching with LLMs** [REF-SCHEMA-LLM] cho thấy mô hình sinh được ứng viên khớp và kích thước ngữ cảnh ảnh hưởng chất lượng; **ReMatch** [REF-REMATCH] tăng cường truy hồi trước khi khớp; **CHESS** [REF-CHESS] tách truy hồi/chọn schema/sinh truy vấn/kiểm thành các giai đoạn và cố ý giảm ngữ cảnh gửi cho mô hình; **RAT-SQL** [REF-RAT-SQL] liên kết schema theo quan hệ thay vì danh sách phẳng; **ToolShed** [REF-TOOLSHED] và **MDB-Link** [REF-MDB-LINK] bàn về cân bằng độ phủ và kích thước ngữ cảnh; **Adaptive-K** [REF-ADAPTIVE-K] được ghi là phương án đã xem và **không chọn**, vì một ngưỡng điểm có thể loại telemetry điểm thấp nhưng vẫn đúng.

Hệ thống áp các nguyên tắc này vào `CapabilityBatcher` và `SourceProfiler`: điểm liên quan chỉ sắp thứ tự xử lý (không có Top-K loại nguồn); ứng viên của mô hình chỉ trở thành năng lực thật sau khi validator đối chiếu census và adapter chạy probe có giới hạn. Điều này chặn lỗi **L2** (thiên kiến kịch bản): nguồn được chọn vì hợp đồng kiểu khớp quan hệ, không vì tên nguồn trùng một từ khóa.

## 2.6. Dùng công cụ an toàn và đánh giá tác tử

- **Verifiably Safe Tool Use** [REF-SAFE-TOOLS] tách ý định khỏi thực thi công cụ đã kiểm.
- **Retrieve-Plan-Generation** [REF-RPG] (EMNLP 2024) lập kế hoạch lặp có điều kiện theo bằng chứng đã lấy.
- **ExCyTIn-Bench** [REF-EXCYTIN] (Microsoft Research) là băng thử tác tử điều tra đa bước trên đồ thị bằng chứng.
- **DARPA Transparent Computing** [REF-DARPA-TC] cung cấp dữ liệu nguồn gốc cho đánh giá.

Các nguồn này nâng đỡ ranh giới: mô hình không gọi nhà cung cấp trực tiếp; ngân sách cuộc gọi/token/truy vấn/thời gian được ghi; độ chính xác ánh xạ nguồn, cạnh bằng chứng và câu trả lời phải đo *riêng*. Chúng không làm một mô hình trở nên đáng tin chỉ vì đã bị giới hạn.

## 2.7. Định vị của hệ thống so với công trình liên quan

Bảng dưới định vị hệ thống so với các nhánh trên:

| Nhánh nghiên cứu | Kế thừa gì | Khác biệt của hệ thống này |
|---|---|---|
| Provenance graph (SLEUTH/HOLMES/OmegaLog) | Đồ thị bằng chứng có trích dẫn | Không ép mọi câu hỏi qua một đồ thị tấn công cố định |
| Typed query (AIQL/ThreatRaptor) | Lớp ngữ nghĩa có kiểu trước cú pháp gốc | Cổng AST tối thiểu kiểm ứng viên SPL do mô hình đề xuất |
| Evidential loop (ECTH/ATHAFI/TaHiTI) | Sự không chắc chắn tường minh | Nhiều quyết định dừng tách biệt, âm tính phải được cấp phép |
| Schema matching bằng LLM (CHESS/ReMatch/…) | Batch có kiểm, giảm ngữ cảnh | Không Top-K loại nguồn; probe xác nhận trước khi tin |
| Safe tool use (SAFE-TOOLS/RPG) | Tách ý định khỏi thực thi | Mô hình không chạm nhà cung cấp; ngân sách ghi lại |

## 2.8. Những gì vẫn là giả thuyết kỹ thuật của kho

Theo `03_LITERATURE-AND-TRACEABILITY.md`, các điểm sau **chưa** được chứng minh bên ngoài: đúng các lớp đồ thị cụ thể; công thức chấm hành động; ngưỡng ngân sách; số cuộc gọi mô hình tối ưu; ngưỡng bằng chứng tối thiểu; khả năng khái quát từ một bộ Splunk sang mọi SIEM; và mọi số F1 chưa có nhãn. Các bài bình duyệt và chuẩn chính thức nâng đỡ *nguyên tắc*; tiền ấn phẩm và tài liệu nhà cung cấp nâng đỡ *thiết kế* với trọng số yếu hơn; một lần chạy lại trong kho chỉ chứng minh đúng hành vi đã đo của lần đó.
