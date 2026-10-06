# Chương 7. Thực nghiệm và đánh giá

Chương này trình bày các lần chạy thật của hệ thống. Mọi con số lấy từ tệp kết quả trong `results/botsv1-peak-run/` và `artifacts/runs/`, hoặc từ lệnh kiểm tra chạy lại khi viết chương này. Phần nào chưa kiểm chứng được sẽ được nêu rõ ở mục 7.9.

## 7.1. Thiết lập thực nghiệm

**Dữ liệu.** CSDL `data/botsv1_eval.sqlite` có 4.417.543 sự kiện trải trên 28 ngày (từ 2016-08-01 đến 2016-08-28), khoảng 154 nghìn dòng mỗi ngày, trừ hai ngày cao hơn là 10/8 (179 nghìn, ngày tấn công Joomla) và 24/8 (224 nghìn, ngày có dữ liệu DNS).

Bảng: Thành phần của CSDL đánh giá
| Loại sự kiện (`native_type`/`event_id`) | Số dòng |
|---|---|
| `process_creation` / 4688 | 3.642.895 |
| `authentication` / 4624 (đăng nhập **thành công**) | 579.580 |
| `smb` / 5140 | 63.859 |
| `web_request` (`stream:http`) | 39.010 |
| `smb` / 5145 | 55.023 |
| `dns` (`stream:dns`, chỉ ngày 24/8) | 35.904 |
| `smb` / 4648 | 1.206 |
| `process_creation` / 1 (sysmon) | 66 |

Điểm cần chú ý ngay: không có sự kiện đăng nhập thất bại (4625), không có tệp, và DNS chỉ có trong một ngày. Điều này quyết định kết quả của ba trong bốn PoC.

**Bốn PoC.** Đây là các PoC có sẵn trong kho, không được viết lại để "chạy được".

Bảng: Bốn PoC thực nghiệm
| PoC | Giả thuyết | Kỹ thuật ATT&CK | Vị từ chính | Cửa sổ |
|---|---|---|---|---|
| `poc-joomla-rce` | Quét và khai thác Joomla trên site nạn nhân | T1190 | `domain EQUALS imreallynotbatman.com` và `cmdline CONTAINS /joomla/` (web) | 10/8, 21:36–22:00 |
| `poc-bruteforce-we1149srv` | Dò mật khẩu tài khoản quản trị | T1110 | `cmdline CONTAINS Logon Failed` và `user EQUALS admin` (authentication) | 21/8, cả ngày |
| `poc-c2-beacon-networkfilter` | Beacon tới tên miền C2 | T1071.001 | `cmdline CONTAINS ad.networkfilter.co` và `/banner/` (web) | 21/8, cả ngày |
| `poc-pdf-exploit-enc` | PowerShell mã hoá, ẩn cửa sổ sau khi mở PDF độc | T1059.001 | `image EQUALS powershell.exe`, `cmdline CONTAINS -enc`, `-w hidden` (process) | 21/8, cả ngày |

**Mô hình LLM và lần chạy.** Ba cấu hình được so sánh: (i) `--offline`, không LLM; (ii) `LLM_MODEL=auto` của OpenRouter (dịch vụ tự chọn mô hình mỗi yêu cầu; một lần nhận thấy được chọn là `deepseek/deepseek-v4.1-flash`); (iii) `nvidia/nemotron-3-super-120b-a12b:free`, mô hình miễn phí. Cùng PEAK Assistant tại commit `dfabbb0`, cùng dữ liệu, cùng PoC. Thực nghiệm chạy trên một máy Windows 11, Python 3.12.

## 7.2. Kết quả chính

Bảng: Kết quả bốn PoC với mô hình `auto`
| PoC | Số bản ghi khớp | Bước khớp | Khuyến nghị | Tin cậy | Judge |
|---|---|---|---|---|---|
| `poc-joomla-rce` | 199 | 2/2 | `ESCALATE_TO_IR` | MEDIUM | TRUE_POSITIVE, 0,88 |
| `poc-bruteforce-we1149srv` | 0 | 0/2 | `CLOSE_WITH_CAVEAT` | MEDIUM | không chạy (không có hit) |
| `poc-c2-beacon-networkfilter` | 0 | 0/2 | `CLOSE_WITH_CAVEAT` | MEDIUM | không chạy |
| `poc-pdf-exploit-enc` | 0 | 0/3 | `CLOSE_WITH_CAVEAT` | MEDIUM | không chạy |

Ghi chú: trong tệp JSON, trường `judge` của ba PoC rỗng được ghi `NO_SIGNAL` với độ tin cậy 0, là giá trị mặc định khi không có hàng để đánh giá, không phải nhận định thật của LLM.

Hai kiểm tra cho thấy phần tất định ổn định: cả ba cấu hình cho cùng số bản ghi khớp (199 và ba lần 0) và cùng các nguồn được phát hiện có dữ liệu.

### 7.2.1. PoC Joomla: có hit, kết luận ở mức vừa phải

Hệ thống tìm thấy 199 bản ghi (99 khớp bước 1, 100 khớp bước 2; mỗi bước giới hạn 100 hàng), tất cả từ một địa chỉ 40.80.148.42 tới `imreallynotbatman.com`, trong khoảng 21:36:45 đến 21:40:57. Các hàng mẫu chứa `/acunetix-wvs-test-for-some-inexistent-file`, đường dẫn ngẫu nhiên tám ký tự và các thành phần `/joomla/index.php/component/search/`: đặc trưng của máy quét Acunetix duyệt thành phần Joomla.

Khuyến nghị là `ESCALATE_TO_IR` nhưng **MEDIUM, không phải HIGH**, và lý do được ghi thẳng trong báo cáo: dữ liệu web chỉ có miền và đường dẫn, không có mã trạng thái, và PoC không có bước nào kiểm tra kết quả, nên chỉ chứng minh được hoạt động quét, chưa chứng minh khai thác thành công. Mục "Rủi ro nếu quyết định sai" do advisor viết nêu đúng điểm này và còn gợi ý rằng mẫu Acunetix có thể là một đợt quét hợp pháp. Đây là hành vi mong muốn: kết luận thận trọng hơn cái mà một nhãn "MATCHED" đơn thuần gợi ra. Báo cáo cũng nhắc người dùng kiểm tra vai trò thật của máy `splunk-02`, vốn là máy ghi log chứ không phải nạn nhân.

Lưu ý lịch sử: phiên bản đầu của bộ luật cho kết quả `HIGH` với cùng bằng chứng. Việc đọc báo cáo đầu tiên mới làm lộ ra rằng độ tin cậy này không có căn cứ; luật trần `outcome_observed` được thêm vào sau đó (mục 4.6.3).

### 7.2.2. Ba PoC rỗng: không phải "sạch"

Ba PoC không có bản ghi khớp. Bảng sau cho thấy vì sao hệ thống không được phép nói "không có tấn công".

Bảng: Độ phủ nguồn của ba PoC rỗng (cửa sổ 21/8)
| PoC | Nguồn cần | Bản ghi nguồn trong cửa sổ | Dữ liệu cần tìm có trong cả CSDL không |
|---|---|---|---|
| `poc-bruteforce-we1149srv` | authentication | 20.657 | Không: chỉ có 4624 (thành công), không có 4625 |
| `poc-c2-beacon-networkfilter` | web | 566 | Không: không có `networkfilter` trong dữ liệu đã nạp |
| `poc-pdf-exploit-enc` | process | 129.775 | Không: không có PowerShell mã hoá thật (các dòng `splunk-powershell.exe` là công cụ của Splunk) |

Nguồn có dữ liệu nên hệ thống không dùng `COLLECT_DATA_THEN_RERUN` mà dùng `CLOSE_WITH_CAVEAT` (MEDIUM), kèm ba giới hạn: nguồn có dữ liệu chưa chắc có đúng loại sự kiện, predicate literal không bắt biến thể, chỉ quét một cửa sổ. Hạn chế thứ nhất đúng là tình trạng thực tế ở đây: đây là điểm hệ thống **chưa tự phát hiện**. Nó chỉ nhắc, và việc kiểm tra loại sự kiện cụ thể phải do người săn làm (mục 8.3).

Mỗi PoC chỉ quét một ngày trong 28 ngày (3,6% khoảng dữ liệu), nên kể cả loại sự kiện có trong dữ liệu, các ngày khác vẫn chưa được xem. Người đọc nên coi kết quả `CLOSE_WITH_CAVEAT` ở đây là "không tìm thấy trong phạm vi đã quét", đúng như nhãn.

## 7.3. So sánh ba cấu hình

Bảng: Cùng bốn PoC dưới ba cấu hình
| PoC | `--offline` | `auto` | Nemotron miễn phí |
|---|---|---|---|
| `poc-joomla-rce` | `INVESTIGATE_FURTHER` (MEDIUM) | `ESCALATE_TO_IR` (MEDIUM) | `ESCALATE_TO_IR` (MEDIUM) |
| `poc-bruteforce-we1149srv` | `CLOSE_WITH_CAVEAT` | `CLOSE_WITH_CAVEAT` | `CLOSE_WITH_CAVEAT` |
| `poc-c2-beacon-networkfilter` | `CLOSE_WITH_CAVEAT` | `CLOSE_WITH_CAVEAT` | `CLOSE_WITH_CAVEAT` |
| `poc-pdf-exploit-enc` | `CLOSE_WITH_CAVEAT` | `CLOSE_WITH_CAVEAT` | `CLOSE_WITH_CAVEAT` |

Ba nhận xét. Thứ nhất, phần quyết định giữa ba cấu hình khác nhau ở đúng một chỗ: judge đóng góp vào Joomla. Không có LLM, hệ thống nói trung thực rằng "chuỗi khớp đủ nhưng chưa ai đánh giá ngữ cảnh" và dừng ở `INVESTIGATE_FURTHER`. Thứ hai, hai mô hình LLM rất khác nhau về nguồn gốc cho cùng kết luận, và độ tin cậy judge dao động nhẹ (0,88 và 0,92; các lần chạy trước từng ra 0,97, 0,92, 0,88), điều này đúng với dự đoán rằng judge không ổn định và nên chỉ dùng làm tham khảo. Thứ ba, ba PoC rỗng không đổi, vì judge không chạy khi không có hàng nào, và luật rỗng không phụ thuộc LLM.

Về chi phí gọi LLM do judge và advisor (số lời gọi và token do bộ đo của hệ thống ghi lại, không tính phần bên trong PEAK vì PEAK không báo token):

Bảng: Số lời gọi và token của judge/advisor
| PoC | `auto`: lời gọi / token | Nemotron: lời gọi / token |
|---|---|---|
| `poc-joomla-rce` | 2 / 7.393 | 2 / 7.877 |
| `poc-bruteforce-we1149srv` | 1 / 6.003 | 1 / 4.124 |
| `poc-c2-beacon-networkfilter` | 1 / 6.561 | 1 / 4.267 |
| `poc-pdf-exploit-enc` | 1 / 6.748 | 1 / 3.663 |

Phần chiếm nhiều thời gian nhất và không được đo token là hai lượt gọi PEAK (ABLE và kế hoạch), mỗi lượt là một cuộc hội thoại đa tác tử nhiều lượt. Đây là hạn chế đo lường ghi ở mục 8.4.

## 7.4. Các lỗi đã phát hiện nhờ thực nghiệm

Giá trị lớn của việc chạy thật nằm ở những thứ kiểm thử đơn vị không bắt được. Bảng sau liệt kê chúng theo thứ tự thời gian.

Bảng: Lỗi phát hiện khi chạy thật và cách xử lý
| # | Hiện tượng | Nguyên nhân | Xử lý |
|---|---|---|---|
| 1 | `image EQUALS powershell.exe` cho 100 hit trên dữ liệu sạch | Tầng tìm `LIKE` khớp cả `splunk-powershell.exe` | Bộ lọc chính xác ở tầng hai, mọi toán tử (từ đánh giá trước đó; có bài hồi quy) |
| 2 | Bước `EXISTS` với giá trị rỗng khớp hàng đầu tiên | Không có điều kiện giá trị | `EXISTS` rỗng trả 0 hàng |
| 3 | Báo `Event loop is closed` sau mỗi lần chạy | Ứng dụng khách HTTP đóng sau vòng lặp | `run_async` và bộ xử lý ngoại lệ im lặng |
| 4 | Lỗi 404 `model_not_found` thoáng qua | Endpoint chuyển yêu cầu tới nhà cung cấp, đôi lần trả 404 | Gọi lại có backoff; đo lại 1/15 (mục 7.5) |
| 5 | Độ tin cậy HIGH cho kết quả chưa chứng minh được thành công | Luật chưa tách quét và khai thác | Trần `outcome_observed` |
| 6 | Advisor trả JSON sai hoặc danh sách rỗng ở 2/4 PoC với `auto` | Mô hình không tuân thủ định dạng | Thử tới 3 lần, chấp nhận nhiều dạng, ghi lý do khi thất bại |
| 7 | `able_table` của PEAK nuốt lỗi thành chuỗi `Error while generating...` | Cách PEAK xử lý ngoại lệ | Nhận ra chuỗi lỗi và coi là lỗi thật để thử lại |

Lỗi số 6 đáng nói thêm. Trước khi sửa, hai trong bốn PoC không có phần bước tiếp theo, và không có cảnh báo nào cho biết LLM đã trả sai: báo cáo trông "hoàn chỉnh" nhưng thiếu một phần. Sau khi sửa, cả bốn PoC có 3 đến 5 bước, 3 đến 5 câu hỏi và 3 đến 5 rủi ro (với Nemotron, số bước/câu hỏi/rủi ro lần lượt là 5/5/5 cho `bruteforce` và Joomla, 4/5/5 cho `c2`, 5/3/3 cho `pdf-exploit`). Lần chạy cuối không có traceback nào trong nhật ký.

## 7.5. Gọi LLM: miễn phí và độ tin cậy của endpoint

### 7.5.1. Đo tỷ lệ lỗi 404

Để chẩn đoán lỗi 404, endpoint chat-completions được gọi trực tiếp 15 lần với mô hình mặc định ban đầu: 14 lần HTTP 200 và 1 lần HTTP 404 `model_not_found` (nhà cung cấp Meta, mô hình `meta/muse-spark-1.3-contributor`). Tỷ lệ khoảng 1/15 (6,7%) nhỏ, nhưng một lần chạy PoC gồm nhiều lời gọi (kể cả hàng chục lời gọi nội bộ của các tác tử PEAK; số này chưa được đo), nên xác suất không gặp lỗi nào giảm nhanh. Ví dụ minh hoạ: với 6,7% mỗi lời gọi và giả sử 30 lời gọi, xác suất không lỗi chỉ khoảng 12%. Đây là lý do cơ chế gọi lại cần thiết chứ không phải tuỳ chọn.

Đổi sang `auto` giải quyết nguồn gốc lỗi vì không còn bị buộc vào một nhà cung cấp hay gặp sự cố. Thử sáu mô hình thay thế: chỉ `auto` chạy ổn định 3/3 lần; năm mô hình còn lại báo "not a valid model ID" trên endpoint hiện tại.

### 7.5.2. Thăm dò mô hình miễn phí

Danh mục OpenRouter được truy vấn qua `/models`, lọc các mô hình có giá prompt và completion bằng 0 (hai kết quả `lyria` là mô hình âm nhạc và một kết quả `content-safety` là mô hình kiểm duyệt nên bị loại khỏi thử nghiệm). Với 17 mô hình còn lại, mỗi mô hình được gọi một lần với yêu cầu trả đúng một đối tượng JSON ngắn (giới hạn 200 token).

Bảng: Kết quả thử một lần các mô hình miễn phí
| Kết quả | Số mô hình | Mô hình |
|---|---|---|
| HTTP 200 và trả JSON hợp lệ | 6 | `nvidia/nemotron-3-super-120b-a12b:free`, `nvidia/nemotron-3-ultra-550b-a55b:free`, `nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free`, `poolside/laguna-s-2.1:free`, `cohere/north-mini-code:free`, `liquid/lfm-2.5-2.6b:free` |
| HTTP 200 nhưng không có JSON trong giới hạn 200 token | 5 | `openrouter/free`, `apodex/apodex-1.1-mini:free`, `inclusionai/ling-3.0-flash-sante:free`, `dots-studio/dots-3-note-preview:free`, `nvidia/nemotron-3.5-lightning:free` |
| HTTP 429 (nhà cung cấp quá tải hoặc giới hạn tốc độ) | 4 | `inclusionai/ling-3.1-flash`, `poolside/laguna-xs-2.1:free`, `google/gemma-4-26b-a4b-it:free`, `google/gemma-4-31b-it:free` |
| HTTP 403 (chỉ dùng trong môi trường tác tử riêng) | 2 | `thinkingmachines/inkling:free`, `thinkingmachines/inkling-small:free` |

Hai điều kiện cần đọc cẩn thận. Một: nhóm "HTTP 200 nhưng không có JSON" có thể là mô hình suy luận dùng hết 200 token để nghĩ trước khi trả lời, nên thử nghiệm này không đủ để kết luận chúng vô dụng. Hai: đây là một lần thử, chưa lặp; HTTP 429 có thể biến mất vào lúc khác. Kết quả chỉ cho biết "gọi được ngay lúc này".

### 7.5.3. Chạy trọn bốn PoC với một mô hình miễn phí

`nvidia/nemotron-3-super-120b-a12b:free` được chọn và chạy trọn bốn PoC (`--model`). Kết quả: cả bốn PoC cho cùng khuyến nghị như `auto`, PEAK được dùng ở cả bốn (`used_peak = true`), không có lần gọi lại nào phải ghi nhận, không có traceback. Judge cho Joomla là TRUE_POSITIVE 0,92. Bảng ABLE và kế hoạch của PEAK vẫn tuân thủ cấu trúc và nhắc đúng nguồn dữ liệu có trong CSDL (ví dụ ABLE của Joomla nói rằng telemetry có `web_request` với trường `domain` và `cmdline`, và gợi ý pivot sang `process_creation` để tìm hậu khai thác).

Kết luận cho yêu cầu ban đầu "gọi được API miễn phí hay không": **có**, ít nhất với một mô hình, và hệ thống chạy trọn vẹn. Đồng thời mục 6.2.2 bảo đảm rằng nếu không có khoá, hệ thống vẫn chạy ở chế độ không LLM.

## 7.6. Kiểm thử đơn vị và tính hồi quy

Bộ kiểm thử có 86 bài: 78 đạt và 8 bị bỏ qua (cần Splunk); `ruff` không báo lỗi. Hai nhóm bài có ý nghĩa cho luận văn.

- **Bất biến kiến trúc được khoá bằng kiểm thử:** chuỗi một phần không escalate; judge dưới ngưỡng không đổi luật; kết quả rỗng khi thiếu nguồn cho `COLLECT_DATA_THEN_RERUN`; advisor lỗi không đổi `disposition`; khoá API không có trong cấu hình.
- **Bài hồi quy cho lỗi thật:** `EQUALS` không khớp `splunk-powershell.exe`; `EXISTS` rỗng không khớp; `retry_async` thành công sau lỗi thoáng qua và ném lại lỗi dai dẳng; CLI chạy được khi không có `.env`.

Quá trình làm gọn kho cũng là một thực nghiệm hồi quy: sau khi xoá khoảng 28.000 dòng mã nguồn và các tệp kiểm thử của engine cũ, đường chạy PoC cho đúng cùng kết quả như trước (Joomla 199 bản ghi, ba PoC còn lại rỗng).

## 7.7. Đánh giá theo yêu cầu

Bảng: Đối chiếu yêu cầu và kết quả
| Yêu cầu | Kết quả | Bằng chứng |
|---|---|---|
| FR1, FR3 | Đạt | Cổng Prepare; 199 hit tái lập |
| FR2 | Đạt | `used_peak = true` ở 4/4 PoC, với hai cấu hình LLM |
| FR4, FR5 | Đạt | Bảng độ phủ; 5 disposition; lựa chọn xếp hạng |
| FR6, FR7 | Đạt | `summary.md`, báo cáo, SPL, backlog |
| FR8 | Đạt | `--offline` và bài `test_cli_runs_without_any_llm_configuration` |
| FR9 | Đạt | `--model` và lần chạy Nemotron |
| NFR1 | Đạt | Mọi hàng đến từ adapter; kiểm thử |
| NFR2 | Đạt | Cùng số bản ghi qua ba cấu hình |
| NFR3 | Đạt từng phần | Gọi lại và fallback có kiểm thử; lỗi 404 thật chỉ có kiểm thử mô phỏng và quan sát gián tiếp |
| NFR4 | Đạt | Quét không thấy khoá trong `artifacts/runs/*`, `results`, `docs` |
| NFR5 | Đạt | Khoảng 8.400 dòng trong `src/` |
| NFR6 | Đạt | Thẻ `v6-engine-final`, nhánh `pre-peak-snapshot` |

## 7.8. Thời gian chạy

Phần tất định rất nhanh: tìm kiếm trên 4,4 triệu dòng mất vài giây mỗi PoC (4 đến 15 giây gồm cả judge). Phần LLM chiếm hầu hết thời gian. Chạy cả bốn PoC với `auto` mất khoảng bốn phút; với mô hình Meta Muse ban đầu mất 4 đến 8 phút cho mỗi PoC (khoảng 16 đến 32 phút cho cả bốn), nên `auto` nhanh hơn rõ rệt. Các con số thời gian phụ thuộc mạnh vào dịch vụ LLM tại thời điểm chạy, chỉ dùng để tham khảo.

## 7.9. Điều chưa được kiểm chứng

Để tránh hiểu nhầm về phạm vi, danh sách sau nêu rõ những điều đồ án chưa làm được.

1. **Splunk thật.** Chưa chạy adapter Splunk hoặc kiểm tra SPL do hệ thống sinh ra trên một máy chủ Splunk.
2. **`--research`.** Tác tử nghiên cứu của PEAK (cần máy chủ MCP) chưa được thử.
3. **Retry trên 404 thật.** Cơ chế gọi lại chỉ được kiểm thử bằng lỗi mô phỏng; trong các lần chạy cuối không gặp lại lỗi 404 nên chưa quan sát nó cứu một lần chạy thật.
4. **Recall.** Chỉ đo được một pha tấn công thật (Joomla); ba pha còn lại thiếu dữ liệu nên chưa đo được khả năng phát hiện. Không có số liệu về độ chính xác tổng thể nào có thể tuyên bố.
5. **Số lần lặp.** Mỗi cấu hình chỉ chạy đầy đủ một đến vài lần; chưa có thống kê về độ biến thiên của judge hoặc advisor ngoài các con số rời rạc đã nêu.
6. **Chất lượng nội dung do PEAK viết.** Hệ thống kiểm tra PEAK có chạy và có trả cấu trúc, nhưng không có người chuyên gia nào chấm chất lượng ABLE hay kế hoạch.
