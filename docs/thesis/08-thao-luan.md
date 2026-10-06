# Chương 8. Thảo luận

## 8.1. Những gì đồ án đạt được

Kết quả quan trọng nhất không nằm ở số liệu mà ở một thay đổi về bản chất của đầu ra. Phiên bản v6 cho người dùng một nhãn (MATCHED hoặc EMPTY) cùng nhận định judge; phiên bản v7 cho một khuyến nghị có cấu trúc: kết luận, mức tin cậy, lý do kiểm chứng được, giới hạn của kết luận, lựa chọn xếp hạng, câu hỏi và rủi ro. Cùng bốn PoC và cùng dữ liệu, sự khác biệt thể hiện rõ nhất ở ba PoC rỗng: nhãn "EMPTY" cũ dễ bị đọc là "không có gì", còn `CLOSE_WITH_CAVEAT` mới buộc người đọc đi qua ba giới hạn trước khi đóng.

Ba điểm thiết kế đáng giữ lại:

1. **Ranh giới tin cậy rõ ràng.** LLM đứng ở hai phía của bộ thực thi (trước: chuẩn bị; sau: giải thích) nhưng không bao giờ ở giữa. Nhờ đó khi LLM sai, thiệt hại giới hạn trong phần văn bản tham khảo.
2. **Luật tất định có giải thích.** Mỗi kết luận có lý do ghi bằng chữ và có kiểm thử khoá hành vi, nên người săn và người phản biện có thể truy vết vì sao hệ thống nói như vậy.
3. **Suy giảm duyên dáng.** Cùng một lệnh chạy được với PEAK, với mô hình miễn phí và không có LLM, và khuyến nghị thay đổi theo cách có thể dự đoán (mục 7.3).

## 8.2. So sánh với phương án thay thế

Bảng: So sánh ba cách tiếp cận
| Tiêu chí | PEAK Assistant dùng riêng | Engine v6 | Hệ thống v7 |
|---|---|---|---|
| Chuẩn bị (ABLE, kế hoạch) | Có, tương tác | Tự xây, cổng kiểm tra trường | Có, qua PEAK, chạy hàng loạt |
| Thực thi trên telemetry | Qua MCP Splunk, do LLM điều khiển | Có, tất định | Có, tất định |
| Kết quả cuối | Tài liệu kế hoạch | Nhãn và nhận định judge | Khuyến nghị có lý do, giới hạn, rủi ro |
| Xử lý kết quả rỗng | Không áp dụng | Nhãn EMPTY | Độ phủ nguồn, `COLLECT_DATA_THEN_RERUN` |
| Chạy khi không có LLM | Không | Một phần | Có, đầy đủ |
| Kích thước mã | Lớn | ~36.400 dòng | ~8.400 dòng |

Đây không phải so sánh hiệu năng; ba hệ thống phục vụ mục đích khác nhau. PEAK Assistant mạnh ở chỗ cộng tác với người săn qua giao diện trò chuyện, điều mà v7 chủ ý không làm: v7 coi PoC là đầu vào đã được người săn chốt.

## 8.3. Hạn chế

### 8.3.1. Khớp literal và độ phủ loại sự kiện

Đây là hạn chế lớn nhất. Vị từ là literal: `-enc` không bắt `-EncodedCommand`, `Logon Failed` không bắt biến thể ngôn ngữ khác. Hệ thống ghi nhận giới hạn này nhưng chưa thử biến thể. Quan trọng hơn là độ phủ theo **nguồn** chưa đủ: nguồn `authentication` có 20.657 bản ghi trong cửa sổ nên hệ thống không báo thiếu dữ liệu, nhưng toàn bộ đó là đăng nhập thành công, trong khi PoC cần đăng nhập thất bại. Một nâng cấp tự nhiên là độ phủ theo **loại sự kiện** (`native_type`, `event_id`) thay vì theo nhóm nguồn; adapter đã có sẵn `describe_data` nên khó khăn chủ yếu ở việc PoC phải khai báo loại sự kiện cần.

### 8.3.2. Cửa sổ thời gian và giới hạn hàng

Mỗi PoC chạy trên một cửa sổ (một ngày hoặc 24 phút) và `max_duration` cắt về ba ngày, nên ba PoC rỗng chỉ phủ 1 trên 28 ngày. Mỗi bước giới hạn 100 hàng, nên con số 199 là mức trần chứ không phải số bản ghi thật (dữ liệu có khoảng 19,7 nghìn dòng Joomla). Báo cáo đang hiển thị "199 bản ghi khớp" mà không nói rõ đã chạm trần; đây là một thiếu sót nên sửa. Bản nháp SPL cũng dùng khoảng thời gian cố định `earliest=-14d` chứ chưa lấy theo cửa sổ của PoC.

### 8.3.3. Vai trò của máy và bối cảnh tổ chức

Máy xuất hiện nhiều nhất trong kết quả Joomla là `splunk-02`, thực chất là máy thu log của bộ dữ liệu chứ không phải nạn nhân. Hệ thống chỉ nhắc người dùng xác nhận vai trò, vì nó không biết sơ đồ tài sản. Kết hợp với CMDB hoặc danh sách tài sản sẽ nâng chất lượng khuyến nghị nhưng nằm ngoài phạm vi.

### 8.3.4. Đo lường chi phí LLM

Số token chỉ tính judge và advisor. Các tác tử bên trong PEAK Assistant tạo ứng dụng khách riêng nên chưa được đo, trong khi đó mới là phần tốn nhất. Muốn đo cần can thiệp vào PEAK hoặc dùng bộ đếm ở tầng proxy.

### 8.3.5. Phụ thuộc vào một dự án chứng minh khái niệm

PEAK Assistant tự nhận là chưa qua kiểm thử bảo mật và không có bản phát hành PyPI. Hệ thống ghim commit để tái lập, nhưng điều đó đồng nghĩa với việc không tự nhận cập nhật và phải kiểm tra lại mỗi khi nâng cấp. Các hàm PEAK dùng (`able_table`, `plan_hunt`) là giao diện nội bộ, không có cam kết ổn định.

### 8.3.6. Tính không tất định của LLM

Cùng bằng chứng nhưng judge có thể cho độ tin cậy khác nhau (0,88 đến 0,97 trong các lần chạy). Thiết kế đã giới hạn ảnh hưởng của sự dao động này (chỉ đẩy một bậc, chỉ khi ≥ 0,7), nhưng ngưỡng 0,7 và 0,8 được chọn theo kinh nghiệm chứ chưa hiệu chỉnh trên tập dữ liệu có nhãn.

## 8.4. Các mối đe dọa đối với tính hợp lệ

**Quy mô nhỏ.** Bốn PoC trên một bộ dữ liệu và một pha tấn công có nhãn. Đồ án chứng minh tính khả thi và các tính chất an toàn của thiết kế, không chứng minh hiệu năng phát hiện tổng quát.

**Dữ liệu đã biết.** BOTS v1 là bộ dữ liệu công khai mà cả PEAK Assistant lẫn mô hình LLM có thể đã thấy trong huấn luyện; việc judge nhận ra chuỗi `acunetix-wvs-test-for-some-inexistent-file` có thể phần nào do kiến thức sẵn có chứ không chỉ do suy luận trên bằng chứng. Với dữ liệu thật của một tổ chức, điều này không đảm bảo.

**Thiên lệch người viết PoC.** Các PoC được viết sau khi đã biết đáp án (từ bản hướng dẫn BOTS v1), nên kết quả Joomla có hit gần như là hiển nhiên. Giá trị kiểm chứng của Joomla là ở cách hệ thống hạ độ tin cậy và nêu giới hạn, không ở việc tìm ra hit.

**Phụ thuộc dịch vụ.** Tỷ lệ lỗi 404 và hành vi mô hình `auto` thay đổi theo thời điểm; kết quả thăm dò mô hình miễn phí là bức ảnh tại một thời điểm.

## 8.5. An toàn và trách nhiệm khi dùng

Khuyến nghị không phải kết luận pháp lý hay lệnh hành động. Hai rủi ro thực tế cần nêu rõ cho người dùng. Thứ nhất, **rò rỉ dữ liệu**: nội dung telemetry rút gọn và mô tả cấu trúc dữ liệu được gửi tới nhà cung cấp LLM; chế độ `--offline` hoặc mô hình cục bộ là lựa chọn cho dữ liệu nhạy cảm. Thứ hai, **tin cậy thái quá**: một báo cáo trình bày đẹp bằng tiếng Việt dễ khiến người đọc bỏ qua giới hạn. Thiết kế đã đặt giới hạn lên cao trong báo cáo và dùng ngôn ngữ trực tiếp, nhưng không thể thay thế sự đào tạo người dùng. Cuối cùng, hệ thống không thực hiện hành động phản ứng nào; mọi bước cô lập, chặn hay xoá đều thuộc về con người.

## 8.6. Bài học rút ra

- Chạy bằng dữ liệu thật quan trọng hơn việc thêm kiểm thử. Các lỗi ở mục 7.4 hầu hết chỉ lộ ra khi chạy trên dữ liệu và LLM thật.
- Đọc báo cáo như một người dùng. Lỗi độ tin cậy HIGH vô căn cứ không làm hỏng bất kỳ bài kiểm thử nào, nó chỉ lộ ra khi đọc câu "chưa chứng minh được thành công" mà vẫn thấy HIGH.
- Đầu ra của LLM cần được kiểm tra về hình thức và về sự vắng mặt: cả hai lỗi 6 và 7 đều ở dạng "trông hợp lệ nhưng thực chất trống hoặc là thông báo lỗi".
- Làm gọn có thể là một đóng góp. Bỏ khoảng 28.000 dòng mã mà không đổi kết quả khiến hệ thống dễ giải thích hơn nhiều, nhưng cần thẻ git để việc bỏ đi không là mất mát.
