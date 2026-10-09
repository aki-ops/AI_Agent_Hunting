# Chương 7. Thực nghiệm và đánh giá

Chương này trình bày các lần chạy thật của hệ thống. Mọi con số lấy từ tệp kết quả trong `results/botsv1-peak-run/` (lần chạy cuối bằng mô hình miễn phí Nemotron) và `artifacts/runs/` (các lần chạy `auto` và so sánh, không đưa vào kho mã), hoặc từ lệnh kiểm tra chạy lại khi viết chương này. Phần nào chưa kiểm chứng được sẽ được nêu rõ ở mục 7.9.

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

Các kết quả dưới đây là của bản hệ thống đã sửa ba lỗi phát hiện ở lượt rà soát cuối (mục 7.4, lỗi 8–10). Bản chạy trước đó cho các kết luận trùng ở bốn PoC nhưng ba PoC rỗng đúng **vì lý do sai**; điểm này được phân tích ở mục 7.2.2.

Bảng: Kết quả bốn PoC với mô hình `auto`
| PoC | Bản ghi hiển thị | Số khớp tổng | Bước khớp | Khuyến nghị | Tin cậy | Judge |
|---|---|---|---|---|---|---|
| `poc-joomla-rce` | 200 | ≥1.999 và ≥2.000 (quét chạm giới hạn) | 2/2 | `ESCALATE_TO_IR` | MEDIUM | TRUE_POSITIVE, 0,85 |
| `poc-bruteforce-we1149srv` | 0 | 0 | 0/2 | `CLOSE_WITH_CAVEAT` | MEDIUM | không chạy (không có hit) |
| `poc-c2-beacon-networkfilter` | 0 | 0 | 0/2 | `CLOSE_WITH_CAVEAT` | MEDIUM | không chạy |
| `poc-pdf-exploit-enc` | 0 | 0 | 0/3 | `CLOSE_WITH_CAVEAT` | MEDIUM | không chạy |

Ghi chú: trong tệp JSON, trường `judge` của ba PoC rỗng được ghi `NO_SIGNAL` với độ tin cậy 0, là giá trị mặc định khi không có hàng để đánh giá, không phải nhận định thật của LLM.

Phần tất định ổn định: cả ba cấu hình (không LLM, `auto`, Nemotron miễn phí) cho cùng số bản ghi hiển thị (200 và ba lần 0) và cùng cơ cấu độ phủ.

### 7.2.1. PoC Joomla: có hit, kết luận ở mức vừa phải

Hệ thống giữ 200 bản ghi làm bằng chứng (100 cho mỗi bước), tất cả từ một địa chỉ 40.80.148.42 tới `imreallynotbatman.com`, trong khoảng 21:36:45 đến 21:40:57. Số khớp thật lớn hơn nhiều: mỗi bước có ít nhất khoảng 2.000 hàng khớp trong cửa sổ 24 phút (lượt quét dừng ở giới hạn 2.000 hàng nên đó chỉ là cận dưới). Phiên bản trước báo "199 bản ghi", một con số do giới hạn 100 hàng và một hàng bị bộ lọc loại, và không cho người đọc biết điều đó; báo cáo hiện ghi `100 / ≥1999` và `100 / ≥2000`. Các hàng mẫu chứa `/acunetix-wvs-test-for-some-inexistent-file`, đường dẫn ngẫu nhiên tám ký tự và các thành phần `/joomla/index.php/component/search/`: đặc trưng của máy quét Acunetix duyệt thành phần Joomla.

Khuyến nghị là `ESCALATE_TO_IR` nhưng **MEDIUM, không phải HIGH**, và lý do được ghi thẳng trong báo cáo: dữ liệu web chỉ có miền và đường dẫn, không có mã trạng thái, và PoC không có bước nào kiểm tra kết quả, nên chỉ chứng minh được hoạt động quét, chưa chứng minh khai thác thành công. Mục "Rủi ro nếu quyết định sai" do advisor viết nêu đúng điểm này và còn gợi ý rằng mẫu Acunetix có thể là một đợt quét hợp pháp. Đây là hành vi mong muốn: kết luận thận trọng hơn cái mà một nhãn "MATCHED" đơn thuần gợi ra. Báo cáo cũng nhắc người dùng kiểm tra vai trò thật của máy `splunk-02`, vốn là máy ghi log chứ không phải nạn nhân.

Lưu ý lịch sử: phiên bản đầu của bộ luật cho kết quả `HIGH` với cùng bằng chứng. Việc đọc báo cáo đầu tiên mới làm lộ ra rằng độ tin cậy này không có căn cứ; luật trần `outcome_observed` được thêm vào sau đó (mục 4.6.3).

### 7.2.2. Ba PoC rỗng: không phải "sạch", và không hề được tìm đúng chỗ

Đây là phát hiện quan trọng nhất của lượt rà soát cuối. Cả ba PoC rỗng có `able.location` chứa tên máy `we1149srv` ("we1149srv authentication log", "egress web traffic from we1149srv", "we1149srv and workstations opening email attachments"). Hàm suy ra phạm vi ABLE biến tên máy đó thành bộ lọc `host = we1149srv` cho **mọi bước**, và điều này không hiện ra trong predicate, báo cáo hay tài liệu. Khi đếm độ phủ trong đúng phạm vi đó, cả ba đều bằng không.

Bảng: Phạm vi truy vấn và độ phủ của ba PoC rỗng (cửa sổ 21/8)
| PoC | Nguồn | Bản ghi nguồn trong cửa sổ | Trong phạm vi `host = we1149srv` | Host thực sự ghi nguồn | Chạy lại không lọc host |
|---|---|---|---|---|---|
| `poc-bruteforce-we1149srv` | authentication | 20.657 | **0** | we9748srv (218), we5364srv (107), we1864srv (75) | 0 bản ghi |
| `poc-c2-beacon-networkfilter` | web | 566 | **0** | splunk-02 (566) | 0 bản ghi |
| `poc-pdf-exploit-enc` | process | 129.775 | **0** | we9748srv (1.335), we5364srv (630), we1864srv (537) | 0 bản ghi |

Với PoC `c2-beacon`, vấn đề mang tính cấu trúc: toàn bộ 39.010 dòng web trong CSDL có `host = splunk-02` (máy thu log), nên bộ lọc theo máy client không thể khớp bất kỳ dòng web nào, kể cả khi beacon có thật. Phiên bản trước báo "nguồn web có 566 bản ghi trong cửa sổ" (đúng nhưng đếm mọi host) trong khi phạm vi tìm kiếm thực tế là 0 dòng; kết luận `CLOSE_WITH_CAVEAT` tình cờ đúng chỉ vì dữ liệu cũng không chứa `networkfilter` ở bất cứ đâu.

Bản đã sửa xử lý phạm vi rỗng thành một trường hợp riêng. Hệ thống đếm độ phủ cả toàn cửa sổ lẫn trong phạm vi host, liệt kê host thực sự ghi nguồn, rồi chạy lại cùng PoC một lần **không lọc host** (thư mục `unscoped_probe/`). Cả ba lần chạy lại đều cho 0 bản ghi, nên khuyến nghị là `CLOSE_WITH_CAVEAT` (MEDIUM) với lý do ghi đủ hai vế: dữ liệu không chứa dấu hiệu ở bất kỳ host nào, và host nêu trong PoC không ghi nguồn này nên PoC chưa từng được thử trên host đó. Kết luận cuối vẫn là `CLOSE_WITH_CAVEAT` như trước, nhưng giờ có lý do đúng và có đo.

Độc lập với phạm vi host, truy vấn trực tiếp trên toàn CSDL (mọi host, mọi ngày) cho 0 dòng với từng chuỗi tín hiệu cần tìm:

Bảng: Dấu hiệu cần tìm có trong dữ liệu không (toàn CSDL 4.417.543 dòng)
| PoC | Dấu hiệu | Số dòng khớp | Loại sự kiện thực có trong nguồn (cửa sổ 21/8) |
|---|---|---|---|
| `poc-bruteforce-we1149srv` | `Logon Failed`; `user = admin` | 0; 0 | chỉ `authentication/4624` (đăng nhập thành công), không có 4625 |
| `poc-c2-beacon-networkfilter` | `networkfilter` | 0 | `web_request` (chỉ có miền và đường dẫn) |
| `poc-pdf-exploit-enc` | `powershell.exe` cùng `-enc`; `-w hidden` | 0; 0 | `process_creation/4688` (các dòng `splunk-powershell.exe` là công cụ của Splunk) |

Cột cuối của bảng hiện nay cũng được hệ thống tự liệt kê trong báo cáo (mục "giới hạn của kết luận"), nên người săn không phải tự truy vấn để biết rằng nguồn xác thực chỉ có đăng nhập thành công. Hệ thống vẫn **chưa tự đối chiếu** loại sự kiện này với predicate; nó chỉ trưng bày để người săn đối chiếu (mục 8.3).

Mỗi PoC chỉ quét một ngày trong 28 ngày (3,6% khoảng dữ liệu), nên kể cả loại sự kiện có trong dữ liệu, các ngày khác vẫn chưa được xem. Người đọc nên coi kết quả `CLOSE_WITH_CAVEAT` ở đây là "không tìm thấy trong phạm vi đã quét", đúng như nhãn.

## 7.3. So sánh ba cấu hình

Bảng: Cùng bốn PoC dưới ba cấu hình
| PoC | `--offline` | `auto` | Nemotron miễn phí |
|---|---|---|---|
| `poc-joomla-rce` | `INVESTIGATE_FURTHER` (MEDIUM) | `ESCALATE_TO_IR` (MEDIUM) | `ESCALATE_TO_IR` (MEDIUM) |
| `poc-bruteforce-we1149srv` | `CLOSE_WITH_CAVEAT` | `CLOSE_WITH_CAVEAT` | `CLOSE_WITH_CAVEAT` |
| `poc-c2-beacon-networkfilter` | `CLOSE_WITH_CAVEAT` | `CLOSE_WITH_CAVEAT` | `CLOSE_WITH_CAVEAT` |
| `poc-pdf-exploit-enc` | `CLOSE_WITH_CAVEAT` | `CLOSE_WITH_CAVEAT` | `CLOSE_WITH_CAVEAT` |

Ba nhận xét. Thứ nhất, phần quyết định giữa ba cấu hình khác nhau ở đúng một chỗ: judge đóng góp vào Joomla. Không có LLM, hệ thống nói trung thực rằng "chuỗi khớp đủ nhưng chưa ai đánh giá ngữ cảnh" và dừng ở `INVESTIGATE_FURTHER`. Thứ hai, hai mô hình LLM rất khác nhau về nguồn gốc cho cùng kết luận, và độ tin cậy judge dao động (0,85 và 0,92 trong lần chạy này; các lần chạy trước từng ra 0,88, 0,92, 0,97), điều này đúng với dự đoán rằng judge không ổn định và nên chỉ dùng làm tham khảo. Thứ ba, ba PoC rỗng không đổi, vì judge không chạy khi không có hàng nào, và luật rỗng không phụ thuộc LLM.

Về chi phí gọi LLM do judge và advisor (số lời gọi và token do bộ đo của hệ thống ghi lại, không tính phần bên trong PEAK vì PEAK không báo token):

Bảng: Số lời gọi và token của judge/advisor
| PoC | `auto`: lời gọi / token | Nemotron: lời gọi / token |
|---|---|---|
| `poc-joomla-rce` | 2 / 9.524 | 2 / 7.280 |
| `poc-bruteforce-we1149srv` | 1 / 7.004 | 1 / 4.814 |
| `poc-c2-beacon-networkfilter` | 1 / 6.695 | 1 / 6.362 |
| `poc-pdf-exploit-enc` | 1 / 8.087 | 1 / 4.949 |

Token tăng so với bản trước vì advisor nhận thêm phạm vi truy vấn, cơ cấu loại sự kiện và kết quả chạy lại. Phần chiếm nhiều thời gian nhất và không được đo token là hai lượt gọi PEAK (ABLE và kế hoạch), mỗi lượt là một cuộc hội thoại đa tác tử nhiều lượt. Đây là hạn chế đo lường ghi ở mục 8.3.

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
| 8 | Ba PoC rỗng bị lọc ngầm theo `host = we1149srv`, host không ghi nguồn tương ứng; độ phủ báo 20.657/566/129.775 bản ghi trong khi phạm vi thực tế là 0 | Host suy ra từ `able.location` không hiển thị trong predicate hay báo cáo | Hiển thị phạm vi; đếm độ phủ trong phạm vi; chạy lại không lọc host; luật riêng (mục 7.2.2) |
| 9 | `MATCHES` với regex thật (`acunet.x`) cho 0 hàng dù `acunetix` cho 6; `EXISTS` dùng tên trường làm từ khoá | Tầng truy xuất đưa nguyên regex vào `LIKE` | Thu hẹp bằng đoạn literal bắt buộc; `EXISTS` đẩy xuống SQL |
| 10 | Joomla báo 199 bản ghi (bước 1 chỉ 99) mà không nói đã chạm giới hạn; SPL dùng `earliest=-14d` cố định | Chỉ lấy 100 hàng rồi mới lọc; cửa sổ SPL không lấy từ PoC | Quét 2.000 hàng rồi lọc, báo `hiển thị / tổng`; SPL dùng cửa sổ của PoC |

Lỗi số 6 đáng nói thêm. Trước khi sửa, hai trong bốn PoC không có phần bước tiếp theo, và không có cảnh báo nào cho biết LLM đã trả sai: báo cáo trông "hoàn chỉnh" nhưng thiếu một phần. Sau khi sửa, cả bốn PoC có đủ 5 bước, 5 câu hỏi và 5 rủi ro với `auto`; với Nemotron là 5/5/5, 5/3/5, 5/5/5 và 5/5/5 (bruteforce, c2, Joomla, pdf-exploit). Lần chạy cuối không có traceback nào trong nhật ký.

Ba lỗi 8–10 được tìm thấy ở lượt rà soát cuối bằng cách đối chiếu mô tả trong luận văn với mã nguồn rồi truy vấn thẳng vào dữ liệu, không phải qua kiểm thử đơn vị. Lỗi 8 đặc biệt đáng nói: kết luận của ba PoC không đổi sau khi sửa, nên một người chỉ nhìn bảng kết quả sẽ không thấy gì khác; sai chỉ nằm ở chỗ PoC chưa từng được tìm đúng chỗ, và chỉ lộ ra khi so cột "bản ghi nguồn trong cửa sổ" với số bản ghi trong phạm vi. Mỗi lỗi có bài hồi quy riêng (`tests/unit/test_scope_and_caps.py`, 15 bài).

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

`nvidia/nemotron-3-super-120b-a12b:free` được chọn và chạy trọn bốn PoC (`--model`), hai lần: một lần trước và một lần sau khi sửa phạm vi truy vấn; số liệu ở chương này là của lần sau. Kết quả: cả bốn PoC cho cùng khuyến nghị như `auto`, PEAK được dùng ở cả bốn (`used_peak = true`), không có lần gọi lại nào phải ghi nhận, không có traceback. Judge cho Joomla là TRUE_POSITIVE 0,92. Bảng ABLE và kế hoạch của PEAK vẫn tuân thủ cấu trúc và nhắc đúng nguồn dữ liệu có trong CSDL (ví dụ ABLE của Joomla nói rằng telemetry có `web_request` với trường `domain` và `cmdline`, và gợi ý pivot sang `process_creation` để tìm hậu khai thác).

Kết luận cho yêu cầu ban đầu "gọi được API miễn phí hay không": **có**, ít nhất với một mô hình, và hệ thống chạy trọn vẹn. Đồng thời mục 6.2.2 bảo đảm rằng nếu không có khoá, hệ thống vẫn chạy ở chế độ không LLM.

### 7.5.4. Các cơ chế vận hành LLM

Joomla được chạy hai lần liên tiếp với `--redact` và mô hình `auto`, dùng cùng thư mục cache.

Bảng: Hai lần chạy Joomla với cache Prepare và che dữ liệu
| Chỉ số | Lần 1 (cache miss) | Lần 2 (cache hit) |
|---|---|---|
| Cache Prepare | chạy mới, đã lưu | dùng lại, PEAK không được gọi |
| Lời gọi LLM (mọi agent) | 9 | 4 |
| Token (mọi agent) | 69.140 | 13.928 |
| Mô hình thực sự trả lời | `deepseek/deepseek-v4.1-flash` | `deepseek/deepseek-v4.1-flash` |
| Phiếu judge | 0,85 / 0,92 / 0,90 | 0,85 / 0,85 / 0,95 |
| Kết luận | `ESCALATE_TO_IR` (MEDIUM) | `ESCALATE_TO_IR` (MEDIUM) |
| Bảng ABLE | giống nhau từng ký tự | giống nhau từng ký tự |

Cache bỏ bước tốn nhất (hai phần PEAK) và cho đúng cùng bảng ABLE. Lần chạy đầu mất khoảng 164 giây tính từ lúc ghi cấu hình đến lúc ra tổng hợp, lần hai khoảng 46 giây. Cả hai lần judge đều thống nhất `TRUE_POSITIVE` nhưng độ tin cậy khác nhau, đúng như đã nêu ở mục 8.3.6. Kiểm tra tay các lời nhắc gửi đi trong bài kiểm thử đầu cuối cho thấy tên máy, tên người dùng và IP không xuất hiện trong văn bản gửi judge và advisor, còn báo cáo vẫn hiện giá trị thật. Mỗi cơ chế (hết ngân sách, chuyển mô hình dự phòng, bỏ temperature khi mô hình từ chối, không cache khi PEAK lỗi) có bài kiểm thử riêng, không cần LLM thật.

## 7.6. Kiểm thử đơn vị và tính hồi quy

Bộ kiểm thử có 146 bài, tất cả đạt; `ruff` không báo lỗi. Tám bài kiểm thử Splunk thật đã đi cùng adapter, chỉ còn ở commit `4dace56`. Hai nhóm bài có ý nghĩa cho luận văn.

- **Bất biến kiến trúc được khoá bằng kiểm thử:** chuỗi một phần không escalate; judge dưới ngưỡng không đổi luật; kết quả rỗng khi thiếu nguồn cho `COLLECT_DATA_THEN_RERUN`; advisor lỗi không đổi `disposition`; khoá API không có trong cấu hình.
- **Bài hồi quy cho lỗi thật:** `EQUALS` không khớp `splunk-powershell.exe`; `EXISTS` rỗng không khớp; `retry_async` thành công sau lỗi thoáng qua và ném lại lỗi dai dẳng; CLI chạy được khi không có `.env`; phạm vi host rỗng được ghi nhận và chạy lại không lọc host (cả nhánh không hit và nhánh có hit ở host khác); báo cáo ghi `hiển thị / tổng`; `MATCHES` với regex thật tìm được; `EXISTS` không bị che bởi giới hạn quét.

Quá trình làm gọn kho cũng là một thực nghiệm hồi quy: sau khi xoá khoảng 28.000 dòng mã nguồn và các tệp kiểm thử của engine cũ, đường chạy PoC cho đúng cùng kết quả như trước (Joomla có hit, ba PoC còn lại rỗng; lúc đó chưa lộ ra các lỗi 8–10).

## 7.7. Đánh giá theo yêu cầu

Bảng: Đối chiếu yêu cầu và kết quả
| Yêu cầu | Kết quả | Bằng chứng |
|---|---|---|
| FR1, FR3 | Đạt | Cổng Prepare; 200 bản ghi hiển thị tái lập qua ba cấu hình |
| FR2 | Đạt | `used_peak = true` ở 4/4 PoC, với hai cấu hình LLM |
| FR4, FR5 | Đạt (sau sửa) | Độ phủ theo cửa sổ, theo host và theo loại sự kiện; 5 disposition; lựa chọn xếp hạng |
| FR6, FR7 | Đạt | `summary.md`, báo cáo, SPL, backlog |
| FR8 | Đạt | `--offline` và bài `test_cli_runs_without_any_llm_configuration` |
| FR9 | Đạt | `--model` và lần chạy Nemotron |
| NFR1 | Đạt | Mọi hàng đến từ adapter; kiểm thử |
| NFR2 | Đạt | Cùng số bản ghi hiển thị qua ba cấu hình |
| NFR3 | Đạt từng phần | Gọi lại và fallback có kiểm thử; lỗi 404 thật chỉ có kiểm thử mô phỏng và quan sát gián tiếp |
| NFR4 | Đạt | Quét không thấy khoá trong `artifacts/runs/*`, `results`, `docs` |
| NFR5 | Đạt | Khoảng 9.400 dòng trong `src/` (gồm luồng Prepare-only) |
| NFR6 | Đạt | Thẻ `v6-engine-final`, nhánh `pre-peak-snapshot` |

## 7.8. Thời gian chạy

Phần tất định nhanh: tìm kiếm trên 4,4 triệu dòng mất vài giây mỗi PoC (6 đến 16 giây gồm cả judge ở lần chạy cuối; quét 2.000 hàng thay vì 100 không làm chậm đáng kể). Phần LLM chiếm hầu hết thời gian. Lần chạy `auto` trước đó mất khoảng bốn phút cho cả bốn PoC, còn lần chạy cuối (ước lượng thô, không bấm giờ chính xác) mất khoảng 12 đến 15 phút cho mỗi cấu hình có LLM; với mô hình Meta Muse ban đầu mất 4 đến 8 phút cho mỗi PoC. Chênh lệch này cho thấy thời gian phụ thuộc mạnh vào dịch vụ LLM tại thời điểm chạy, các con số chỉ dùng để tham khảo.

## 7.9. Điều chưa được kiểm chứng

Để tránh hiểu nhầm về phạm vi, danh sách sau nêu rõ những điều đồ án chưa làm được.

1. **Splunk thật.** Chưa kiểm tra SPL do hệ thống sinh ra (bản nháp ở pipeline PoC và truy vấn trong kế hoạch Prepare-only) trên một máy chủ Splunk.
2. **`--research`.** Tác tử nghiên cứu của PEAK (cần máy chủ MCP) chưa được thử.
3. **Mô hình dự phòng trên lỗi thật.** Việc chuyển mô hình dự phòng chỉ được kiểm thử bằng lỗi mô phỏng, chưa gặp lỗi thật trong các lần chạy. **Retry trên 404 thật.** Cơ chế gọi lại chỉ được kiểm thử bằng lỗi mô phỏng; trong các lần chạy cuối không gặp lại lỗi 404 nên chưa quan sát nó cứu một lần chạy thật.
4. **Adapter Splunk với các thay đổi truy xuất mới.** Adapter đã được gỡ khỏi nhánh chính (còn ở commit `4dace56`); giới hạn quét 2.000 hàng và tham số `require_nonempty` chưa được chạy trên Splunk thật ở đó, và adapter chưa có độ phủ theo host hay theo loại sự kiện.
5. **Recall.** Chỉ đo được một pha tấn công thật (Joomla); ba pha còn lại thiếu dữ liệu nên chưa đo được khả năng phát hiện. Không có số liệu về độ chính xác tổng thể nào có thể tuyên bố.
6. **Số lần lặp.** Mỗi cấu hình chỉ chạy đầy đủ một đến vài lần; chưa có thống kê về độ biến thiên của judge hoặc advisor ngoài các con số rời rạc đã nêu.
7. **Chất lượng nội dung do PEAK viết.** Hệ thống kiểm tra PEAK có chạy và có trả cấu trúc, nhưng không có người chuyên gia nào chấm chất lượng ABLE hay kế hoạch.

## 7.10. Thực nghiệm luồng Prepare-only

Mục này báo cáo các lần chạy của luồng mới với mô hình miễn phí `nvidia/nemotron-3-super-120b-a12b:free` (số dư tài khoản không đổi sau mọi lần chạy). Không có lần chạy nào dùng dữ liệu nội bộ; kết quả thực thi trong thử nghiệm xác minh là giả lập và được nêu rõ.

### 7.10.1. Hai CVE công khai

Bảng: Các lần lập kế hoạch từ PoC công khai
| CVE | Cấu hình | Kho PoC | Giai đoạn | Truy vấn | Độ phủ | Lời gọi LLM | Token |
|---|---|---|---|---|---|---|---|
| Log4Shell (CVE-2021-44228) | có PEAK | 3 kho, ≥ 1.800 sao | 3 | 7 | 4 | 18 | 375.916 (khoảng 10 phút) |
| Log4Shell | `--no-peak`, bản đầu | 3 kho | 4 | 8 | — | — | khoảng 16–19 nghìn |
| Log4Shell | `--no-peak`, sau hai quy tắc mới | 3 kho | 3 | 4 | 3 | 1 | 13.142 |
| Spring4Shell (CVE-2022-22965) | có PEAK, bản sửa | 3 kho (2.351, 376, 325 sao) | 4 | 4 | 2 | — | — |
| Spring4Shell | `--no-peak`, sau hai quy tắc mới | 3 kho | 3 | 3 | 2 | 2 | 22.726 |

Các con số "—" là chỗ không còn ghi lại được. Phần PEAK chiếm hầu hết token, tương tự pipeline PoC (mục 7.8). Mỗi dòng là *một* lần chạy với mô hình không tất định, nên bảng cho thấy cỡ độ lớn chứ không cho thấy hiệu quả của từng quy tắc.

Một số quan sát cụ thể:

- **Dấu vết đúng đặc trưng.** Với Spring4Shell, danh sách ứng viên ban đầu thiếu `class.module.classLoader...`, dấu hiệu cốt lõi của lỗ hổng. Nguyên nhân là biểu thức chính quy chỉ nhận tham số dạng đơn giản, và README chiếm hết chỗ trước tệp khai thác. Sau khi sửa biểu thức (tham số có dấu chấm, header tuỳ biến) và ưu tiên tệp khai thác trước README trong bản tóm tắt, các lần chạy đều có dấu hiệu này, cùng `tomcatwar.jsp` và `spring-form.war`.
- **Lỗi thật khi lập kế hoạch.** Lần đầu có PEAK trên Spring4Shell, mô hình viết dấu ngoặc kép lệch trong SPL ở cả ba lượt sửa ("unbalanced double quote") nên không còn truy vấn hợp lệ nào và chương trình dừng với `PlanError`. Lời nhắc sửa lỗi được bổ sung gợi ý cụ thể (truy vấn đơn giản, đoạn ngắn ổn định thay vì dán payload có dấu ngoặc kép); lần chạy sau đạt.
- **Quy tắc tiến trình cha.** Trong lần chạy Log4Shell `--no-peak` gần nhất, giai đoạn `impact` có một truy vấn endpoint mà mô hình tự viết với `parent_process_name="java"`, và không có truy vấn nào bị loại. Đây chỉ cho thấy lời nhắc mới được mô hình làm theo trong một lần chạy, không phải bằng chứng rằng quy tắc luôn được tuân thủ; các bài kiểm thử đơn vị mới khoá phần mã (truy vấn thiếu tiến trình cha bị gửi lại, rồi bị loại nếu không sửa).
- **Chữ lẫn ngôn ngữ.** Trước khi có bộ phát hiện, `plan.md` của Spring4Shell có các từ "przeciwko" (tiếng Ba Lan), "tentativa" (Bồ Đào Nha), "ungewö" (Đức) và "explotación" (Tây Ban Nha) lẫn trong câu tiếng Việt, mà bộ lọc ký tự không bắt được. Trong lần chạy Spring4Shell sau khi có bộ phát hiện, nó gắn cờ từ `debug`, một từ tiếng Anh hợp lệ chưa có trong từ vựng, và tốn thêm một lời gọi viết lại (22.726 token cho hai lời gọi). Từ vựng đã được bổ sung `debug` cùng các từ kỹ thuật cùng loại; đây là chi phí điển hình của một dương tính giả.
- **Một giai đoạn không còn truy vấn** (khi quy tắc loại hết truy vấn của nó) trước đây sẽ bị `verify` đọc là `CLEAR`. Đã sửa: giai đoạn đó là `INCOMPLETE`, `plan.md` in cảnh báo, và có bài kiểm thử.

### 7.10.2. Đo bộ phát hiện ngôn ngữ

Hai phép đo nhỏ trên chính mã (không phải trên đầu ra LLM):

- **Độ nhạy:** 62 từ ngoại ngữ thật thuộc chín ngôn ngữ (Bồ Đào Nha, Tây Ban Nha, Đức, Pháp, Ba Lan, Ý, Indonesia, Hà Lan, Thổ Nhĩ Kỳ), mỗi từ đặt vào một câu tiếng Việt: bắt được 62/62 (một tập con của danh sách này nằm trong bài kiểm thử đơn vị). Từ ngắn dưới 4 chữ cái cố ý không xét nên không nằm trong phép đo, và danh sách do tác giả chọn nên 62/62 không phải độ nhạy trên đầu ra thật của mô hình.
- **Dương tính giả:** chạy trên khoảng 17.000 từ văn xuôi tiếng Việt xen thuật ngữ tiếng Anh (README, hai tài liệu thiết kế, báo cáo và sáu chương đầu của luận văn), không từ tiếng Việt nào bị gắn cờ. Lần đầu có 126 từ khác nhau bị gắn cờ, toàn từ tiếng Anh kỹ thuật (`judge`, `adapter`, `placeholder`...); sau khi bổ sung từ vựng còn 8 từ khác nhau (11 lần xuất hiện, như `temperature`, `pytest`, `ruff`). **Từ vựng được chỉnh trên chính tập này, nên con số 8 là lạc quan;** dương tính giả trên văn bản mới sẽ cao hơn, và chi phí của nó là một lời gọi viết lại.

### 7.10.3. Vòng xác minh bằng kết quả giả lập

Vòng `verify` được thử với `ResultBundle` do tác giả dựng tay (nêu rõ là giả lập) trên kế hoạch Log4Shell. Vòng 1 cho `REFINE`: thư mục `iter2/` chứa các giai đoạn pivot theo nguồn tấn công và host bị nhắm, cửa sổ thu về một giờ quanh các mốc thời gian trong mẫu. Vòng 2, sau khi kết quả giả lập cho truy vấn pivot ở giai đoạn `impact` có dòng, cho `ESCALATE_AFFECTED`. Đây chỉ chứng minh bộ máy chạy đúng logic đã thiết kế, không chứng minh pivot tìm đúng thứ cần tìm. Các bài kiểm thử đơn vị phủ thêm các nhánh còn lại: kết quả toàn rỗng thành `ACCEPT_NO_EVIDENCE` kèm câu "không phải kết luận sạch"; nguồn rỗng thành `COLLECT_DATA`; truy vấn lỗi hoặc thiếu thành `RERUN_INCOMPLETE`; `plan_id` sai thành `REJECT_RESULTS`; giá trị chứa ký tự nguy hiểm không được nhúng vào truy vấn pivot; số vòng tối đa dừng ở `STOP_REVIEW`.

### 7.10.4. Điều chưa kiểm chứng ở luồng này

- Mọi truy vấn trong kế hoạch **chưa chạy trên Splunk thật**, kể cả truy vấn độ phủ `tstats`; tên trường theo CIM có thể khác ở mỗi nơi.
- Vòng `verify` chưa nhận **kết quả thật** của một đội thực thi.
- Chất lượng truy vấn (có bắt đúng tấn công không) chưa được chuyên gia chấm; bộ kiểm tra chỉ đảm bảo an toàn và hình thức.
- Hai quy tắc mới (tiến trình cha, ngôn ngữ) mới được thử bằng bài kiểm thử đơn vị và vài lần chạy không PEAK; chưa chạy lại cấu hình có PEAK sau khi thêm chúng.
- Chọn PoC theo số sao là tín hiệu yếu; kho có thể lỗi thời, đã lưu trữ hoặc sai (kế hoạch ghi cảnh báo `archived`, `below_threshold`).
