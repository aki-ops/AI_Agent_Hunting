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
| Kích thước mã | Lớn | ~36.400 dòng | ~9.200 dòng |

Đây không phải so sánh hiệu năng; ba hệ thống phục vụ mục đích khác nhau. PEAK Assistant mạnh ở chỗ cộng tác với người săn qua giao diện trò chuyện, điều mà v7 chủ ý không làm: v7 coi PoC là đầu vào đã được người săn chốt.

## 8.3. Hạn chế

### 8.3.1. Khớp literal và độ phủ loại sự kiện

Vị từ là literal: `-enc` không bắt `-EncodedCommand`, `Logon Failed` không bắt biến thể ngôn ngữ khác. Hệ thống ghi nhận giới hạn này nhưng chưa thử biến thể. Độ phủ theo **nguồn** không đủ: nguồn `authentication` có 20.657 bản ghi trong cửa sổ nhưng toàn bộ là đăng nhập thành công, trong khi PoC cần đăng nhập thất bại. Sau lượt rà soát cuối, báo cáo của kết quả rỗng liệt kê các loại sự kiện thực có (`authentication/4624 (20.657)`) để người săn tự đối chiếu, nhưng hệ thống **vẫn chưa tự so** chúng với predicate: điều đó đòi hỏi PoC khai báo loại sự kiện cần có (ví dụ `required_event_types`), một thay đổi định dạng PoC còn để ngỏ.

### 8.3.2. Phạm vi truy vấn ngầm, cửa sổ thời gian và giới hạn hàng

Đây là điểm yếu thiết kế đã bộc lộ và được xử lý một phần ở lượt rà soát cuối. Phạm vi suy ra từ ABLE của PoC (host trong `able.location`, chuỗi cụ thể trong `able.behavior`) được thêm vào mọi bước. Cơ chế này có ý đồ tốt (PEAK muốn ABLE dẫn dắt truy vấn) nhưng nguy hiểm khi tên máy trong `location` chỉ mang tính mô tả: ở cả ba PoC rỗng, máy đó không ghi nguồn tương ứng nên PoC chưa từng tìm trên dữ liệu thật (mục 7.2.2). Đồ án đã làm ba việc: hiển thị phạm vi, đếm độ phủ trong phạm vi, và chạy lại không lọc host khi phạm vi rỗng. Nhưng gốc vấn đề vẫn còn: việc đọc tên máy từ văn xuôi bằng biểu thức chính quy vẫn là heuristic, có thể chọn nhầm token; một thiết kế sạch hơn là tách một trường `host_scope` tường minh trong PoC.

Về cửa sổ, mỗi PoC chạy trên một cửa sổ (một ngày hoặc 24 phút) và `max_duration` cắt về ba ngày, nên ba PoC rỗng chỉ phủ 1 trên 28 ngày. Về giới hạn hàng, mỗi bước quét tối đa 2.000 hàng và giữ 100 hàng làm bằng chứng; báo cáo hiện ghi `hiển thị / tổng` và dấu `≥` khi quét chạm trần, nhưng số tổng khi bị cắt vẫn chỉ là cận dưới (PoC Joomla có khoảng 19,7 nghìn dòng Joomla trong cả tập dữ liệu). Muốn có số chính xác cần truy vấn `COUNT` riêng. Bản nháp SPL nay dùng cửa sổ của PoC (đổi sang epoch) nhưng chưa thêm bộ lọc host của phạm vi, nên bản nháp phát hiện rộng hơn PoC.

### 8.3.3. Vai trò của máy và bối cảnh tổ chức

Máy xuất hiện nhiều nhất trong kết quả Joomla là `splunk-02`, thực chất là máy thu log của bộ dữ liệu chứ không phải nạn nhân. Hệ thống chỉ nhắc người dùng xác nhận vai trò, vì nó không biết sơ đồ tài sản. Kết hợp với CMDB hoặc danh sách tài sản sẽ nâng chất lượng khuyến nghị nhưng nằm ngoài phạm vi.

### 8.3.4. Đo lường chi phí LLM

Bản đầu chỉ đếm token của judge và advisor, trong khi các tác tử bên trong PEAK mới là phần tốn nhất. Hiện nay `UsageMeter` bọc hàm tạo hoàn thành trò chuyện của SDK OpenAI nên đếm cả hai. Một lần chạy Joomla với `auto` cho thấy khoảng cách: judge và advisor dùng 16.116 token, còn toàn bộ chuỗi là 69.140 token trong 9 lời gọi, tức PEAK chiếm khoảng bốn phần năm. Giới hạn còn lại là các lời gọi dạng stream không trả khối `usage`; chúng chỉ được đếm số lần (`llm_unmetered_calls`). Trong các lần chạy đã thực hiện số này bằng 0. Người dùng có thể đặt trần bằng `--token-budget`.

### 8.3.5. Phụ thuộc vào một dự án chứng minh khái niệm

PEAK Assistant tự nhận là chưa qua kiểm thử bảo mật và không có bản phát hành PyPI. Hệ thống ghim commit để tái lập, nhưng điều đó đồng nghĩa với việc không tự nhận cập nhật và phải kiểm tra lại mỗi khi nâng cấp. Các hàm PEAK dùng (`able_table`, `plan_hunt`) là giao diện nội bộ, không có cam kết ổn định.

### 8.3.6. Tính không tất định của LLM

Cùng bằng chứng nhưng judge có thể cho độ tin cậy khác nhau (0,85 đến 0,97 trong các lần chạy). Thiết kế đã giới hạn ảnh hưởng của sự dao động này (chỉ đẩy một bậc, chỉ khi ≥ 0,7), nhưng ngưỡng 0,7 và 0,8 được chọn theo kinh nghiệm chứ chưa hiệu chỉnh trên tập dữ liệu có nhãn. Để giảm dao động, judge nay chạy ở temperature 0 và ba lần, lấy đa số với độ tin cậy thấp nhất trong nhóm đa số. Ở temperature 0 hai lần chạy liên tiếp vẫn cho ba phiếu khác nhau (0,85/0,92/0,90 rồi 0,85/0,85/0,95) dù cùng nhãn `TRUE_POSITIVE`, nên temperature 0 không đảm bảo kết quả lặp lại; bỏ phiếu chỉ làm lộ và giảm độ lệch. Mô hình `auto` còn có thể đổi nhà cung cấp giữa các lần, vì vậy báo cáo ghi mô hình thực sự trả lời (`deepseek/deepseek-v4.1-flash` trong hai lần chạy này) và khi cần tái lập nên cố định `--model`.

## 8.4. Các mối đe dọa đối với tính hợp lệ

**Quy mô nhỏ.** Bốn PoC trên một bộ dữ liệu và một pha tấn công có nhãn. Đồ án chứng minh tính khả thi và các tính chất an toàn của thiết kế, không chứng minh hiệu năng phát hiện tổng quát.

**Dữ liệu đã biết.** BOTS v1 là bộ dữ liệu công khai mà cả PEAK Assistant lẫn mô hình LLM có thể đã thấy trong huấn luyện; việc judge nhận ra chuỗi `acunetix-wvs-test-for-some-inexistent-file` có thể phần nào do kiến thức sẵn có chứ không chỉ do suy luận trên bằng chứng. Với dữ liệu thật của một tổ chức, điều này không đảm bảo.

**Thiên lệch người viết PoC.** Các PoC được viết sau khi đã biết đáp án (từ bản hướng dẫn BOTS v1), nên kết quả Joomla có hit gần như là hiển nhiên. Giá trị kiểm chứng của Joomla là ở cách hệ thống hạ độ tin cậy và nêu giới hạn, không ở việc tìm ra hit.

**Phụ thuộc dịch vụ.** Tỷ lệ lỗi 404 và hành vi mô hình `auto` thay đổi theo thời điểm; kết quả thăm dò mô hình miễn phí là bức ảnh tại một thời điểm.

## 8.5. An toàn và trách nhiệm khi dùng

Khuyến nghị không phải kết luận pháp lý hay lệnh hành động. Hai rủi ro thực tế cần nêu rõ cho người dùng. Thứ nhất, **rò rỉ dữ liệu**: nội dung telemetry rút gọn và mô tả cấu trúc dữ liệu được gửi tới nhà cung cấp LLM; chế độ `--offline`, mô hình cục bộ hoặc ít nhất `--redact` là lựa chọn cho dữ liệu nhạy cảm (nhưng `--redact` không che chuỗi tự do). Thứ hai, **tin cậy thái quá**: một báo cáo trình bày đẹp bằng tiếng Việt dễ khiến người đọc bỏ qua giới hạn. Thiết kế đã đặt giới hạn lên cao trong báo cáo và dùng ngôn ngữ trực tiếp, nhưng không thể thay thế sự đào tạo người dùng. Cuối cùng, hệ thống không thực hiện hành động phản ứng nào; mọi bước cô lập, chặn hay xoá đều thuộc về con người.

## 8.6. Bài học rút ra

- Chạy bằng dữ liệu thật quan trọng hơn việc thêm kiểm thử. Các lỗi ở mục 7.4 hầu hết chỉ lộ ra khi chạy trên dữ liệu và LLM thật.
- Một kết luận đúng chưa chắc có lý do đúng. Ba PoC rỗng cho cùng khuyến nghị trước và sau khi sửa, nhưng trước đó chúng chưa từng tìm đúng chỗ. Chỉ khi đối chiếu cột "bản ghi nguồn trong cửa sổ" với "trong phạm vi lọc" và truy vấn trực tiếp dữ liệu thì mới thấy. Bài học: mọi bộ lọc ngầm phải hiện ra trong báo cáo, và mọi con số độ phủ phải đếm đúng phạm vi mà truy vấn thực sự chạy.
- Tự đối chiếu tài liệu với mã. Mô tả "MATCHES dùng `re.search`" trong bản thảo luận văn đúng ở tầng lọc nhưng sai ở tầng truy xuất; lỗi chỉ lộ ra khi đọc lại mã khi rà soát.
- Đọc báo cáo như một người dùng. Lỗi độ tin cậy HIGH vô căn cứ không làm hỏng bất kỳ bài kiểm thử nào, nó chỉ lộ ra khi đọc câu "chưa chứng minh được thành công" mà vẫn thấy HIGH.
- Đầu ra của LLM cần được kiểm tra về hình thức và về sự vắng mặt: cả hai lỗi 6 và 7 đều ở dạng "trông hợp lệ nhưng thực chất trống hoặc là thông báo lỗi".
- Làm gọn có thể là một đóng góp. Bỏ khoảng 28.000 dòng mã mà không đổi kết quả khiến hệ thống dễ giải thích hơn nhiều, nhưng cần thẻ git để việc bỏ đi không là mất mát.

## 8.7. Hạn chế và rủi ro của hướng Prepare-only

**Kiểm tra an toàn không phải kiểm tra đúng.** `check_spl` chứng minh một truy vấn chỉ đọc và có giới hạn, không chứng minh nó bắt đúng tấn công. Ví dụ điển hình: truy vấn trên đường dẫn `/greeting` của ứng dụng minh hoạ trong PoC trông hợp lệ nhưng ít khi trùng hệ thống thật; truy vấn trên `uri_query` bỏ sót kiểu tấn công gửi tham số trong thân POST vì nhật ký web thường không ghi thân. Người săn phải đọc `plan.md` trước khi giao đi.

**Điểm dừng chủ yếu là khai báo.** `verify` chỉ thực sự đọc hành động `escalate` từ kế hoạch; các hành động khác (`narrow`, `collect_data`, `stop_stage`) được ghi vào báo cáo nhưng quyết định cuối do thứ tự cố định ở mục 4.9.4. Sửa tay `stop_conditions` ngoài `escalate` sẽ không đổi hành vi.

**"Kết quả" là số dòng.** Một truy vấn `stats count by src` trúng 1.000 sự kiện từ ba nguồn chỉ trả ba dòng. Ngưỡng và trần dòng vì vậy phản ánh độ rộng của kết quả hơn là số sự kiện.

**Quy tắc tiến trình cha dựa vào mô hình biết tên tiến trình.** Ép lọc theo tiến trình cha làm giảm báo nhầm, nhưng nếu mô hình chọn sai họ tiến trình (ví dụ `java` cho một dịch vụ chạy bằng `javaw` hay bằng tên đóng gói khác) thì truy vấn hợp lệ về hình thức nhưng bỏ sót. Các truy vấn pivot do mã sinh (`P2`) không có ràng buộc này vì mã không biết dịch vụ; chúng bị giới hạn bằng host và cửa sổ thời gian, và kết quả của chúng luôn cần người đọc, vì mã không có đường cơ sở để phân biệt shell hợp lệ.

**Bộ phát hiện ngôn ngữ là heuristic.** Từ vựng tiếng Anh do tác giả soạn nên dương tính giả có chi phí là một lời gọi; từ ngoại ngữ ngắn hơn 4 chữ cái, tên riêng viết hoa đầu câu, và từ ngoại ngữ trùng một âm tiết tiếng Việt hợp lệ sẽ lọt. Nó chỉ bảo vệ chất lượng văn bản cho người đọc, không phải một biện pháp an ninh.

**Hạn mức và tính ổn định của nguồn.** GitHub không token chỉ cho 60 yêu cầu mỗi giờ; kết quả tìm kiếm theo số sao thay đổi theo thời gian, nên cùng lệnh có thể ra tập kho khác. Mô hình miễn phí cho chất lượng không đều (lỗi ngoặc kép, chữ ngoại ngữ) và mỗi lần chạy khác nhau.

**Rủi ro an ninh của chính đầu vào.** README và mã PoC có thể chứa lệnh giả mạo nhắm vào LLM (prompt injection). Giảm thiểu bằng hàng rào dữ liệu và nhãn không tin cậy, nhưng quan trọng hơn là *đầu ra của LLM không bao giờ được thực thi và không bao giờ rời dự án mà chưa qua kiểm tra tĩnh*, nên kịch bản xấu nhất là kế hoạch kém chất lượng chứ không phải lệnh nguy hiểm. Dự án cũng không tải hay chạy mã PoC; nó chỉ đọc văn bản.

**Đánh giá lại hướng đi.** So với pipeline cũ, hướng Prepare-only đánh đổi khả năng tự kiểm tra trên dữ liệu thật để lấy ranh giới dữ liệu sạch. Đổi lại, phần khó nhất là phần dự án không còn kiểm soát: chất lượng truy vấn khi chạy ở môi trường khác. Cách giảm rủi ro hợp lý là hợp đồng dữ liệu rõ (schema, truy vấn độ phủ, `ACCEPT_NO_EVIDENCE` không là "sạch") và một vòng phản hồi qua `verify`, đúng những gì dự án đã làm; nhưng vòng đó chưa được kiểm chứng với kết quả thật.
