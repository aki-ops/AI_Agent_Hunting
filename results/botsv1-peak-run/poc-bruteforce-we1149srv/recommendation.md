# Khuyến nghị hunt — `poc-bruteforce-we1149srv`

**PoC:** Brute force login against public-facing server  
**Cửa sổ dữ liệu:** `2016-08-21T00:00:00Z/2016-08-22T00:00:00Z`  
**Nguồn dữ liệu:** CDB data/botsv1_eval.sqlite  
**PEAK Assistant:** đã dùng (ABLE + hunt plan)

## Khuyến nghị

### Đóng, kèm cảnh báo giới hạn
`CLOSE_WITH_CAVEAT` — độ tin cậy **trung bình** (MEDIUM).

> Đây là gợi ý hỗ trợ quyết định. **Người săn mối đe dọa là người quyết định cuối cùng**; hệ thống không tự hành động.

**Lý do**

- Không có bản ghi nào khớp bất kỳ bước nào của PoC trong cửa sổ đã chạy.
- Nguồn `authentication` có 20,657 bản ghi trong cửa sổ nhưng 0 bản ghi của host `we1149srv` (host lọc suy ra từ `able.location`); host thực sự ghi nguồn này: we9748srv (218), we5364srv (107), we1864srv (75).
- Chạy lại cùng PoC KHÔNG lọc host: 0 bản ghi khớp ở bất kỳ host nào trong cửa sổ. Dữ liệu hiện có không chứa dấu hiệu này ở đâu cả, nhưng phát hiện này chỉ đúng với predicate literal, loại sự kiện đang có và cửa sổ đã quét; host nêu trong PoC không hề ghi nguồn này nên PoC chưa từng được thử trên host đó.

**Cần lưu ý (giới hạn của kết luận)**

- Nguồn có dữ liệu chưa chắc chứa đúng loại sự kiện cần tìm (ví dụ chỉ có đăng nhập thành công, không có đăng nhập thất bại); hệ thống chưa tự đối chiếu với predicate.
- Loại sự kiện của nguồn `authentication` trong cửa sổ (mọi host): authentication/4624 (20,657). Hãy xác nhận loại sự kiện mà PoC cần (ví dụ đăng nhập thất bại 4625) có trong danh sách này.
- PoC chỉ kiểm tra các predicate literal đã khai báo; biến thể (obfuscation, tên khác, field khác) không được thử.
- Chỉ quét cửa sổ 2016-08-21T00:00:00Z/2016-08-22T00:00:00Z; hoạt động ngoài cửa sổ không được xem.
- Ngoài predicate của từng bước, truy vấn còn bị giới hạn bởi các điều kiện suy ra từ ABLE của PoC: host = `we1149srv`.

## Các lựa chọn cho người quyết định (xếp theo ưu tiên)

| # | Hành động | Việc cần làm |
|---|---|---|
| 1 | `CLOSE_WITH_CAVEAT` (Đóng, kèm cảnh báo giới hạn) | Đóng hunt, ghi rõ giới hạn; cân nhắc mở rộng cửa sổ hoặc biến thể predicate trước khi coi là sạch. |
| 2 | `COLLECT_DATA_THEN_RERUN` (Bổ sung telemetry rồi chạy lại) | Kiểm tra phạm vi host của PoC (`we1149srv`): nguồn authentication có dữ liệu nhưng ở host khác; sửa `able.location` hoặc bổ sung telemetry của host đó rồi chạy lại. |

## Bằng chứng

| Bước | Predicate | Nguồn | Bản ghi nguồn trong cửa sổ | Trong phạm vi lọc | Khớp (hiển thị / tổng) |
|---|---|---|---|---|---|
| `s1-failed-auth` | `cmdline CONTAINS Logon Failed` | authentication | 20,657 | 0 | 0 |
| `s2-targeted-user` | `user EQUALS admin` | authentication | 20,657 | 0 | 0 |

**Phạm vi truy vấn thực tế** (ngoài predicate, suy ra từ ABLE của PoC):
- host = `we1149srv`

Tổng 0 bản ghi hiển thị làm bằng chứng; 0/2 bước có kết quả.

## Judge (LLM, chỉ tham khảo)

**NO_SIGNAL** — độ tin cậy 0.00

No adapter hits and no escalation evidence; result is 'absence of evidence', not 'evidence of absence'.
- skipped_llm

## Gợi ý bước tiếp theo (từ kế hoạch PEAK, LLM)

1. **Chạy lại predicate cmdline CONTAINS 'Logon Failed' trên toàn bộ cửa sổ khuyến nghị 2016-08-01T00:00:00Z/2016-08-28T23:59:00Z, không lọc host, nguồn authentication; sau đó lọc riêng host we1149srv để xác nhận có/không có bản ghi.** — Cửa sổ đã chạy chỉ 2016-08-21, còn PEAK khuyến nghị 28 ngày; host we1149srv có 0 bản ghi authentication nên cần kiểm tra lại toàn cửa sổ.
2. **Liệt kê giá trị distinct của host trong nguồn authentication/4624, đối chiếu với source_hosts (we9748srv, we5364srv, we1864srv), và xác minh ánh xạ host we1149srv từ able.location.** — Scope host we1149srv không ghi nhận nguồn authentication; cần loại trừ sai tên host hoặc sai ánh xạ tài sản.
3. **Thống kê top giá trị của trường action và status trên bản ghi authentication/4624 trong cửa sổ, tìm giá trị thể hiện thất bại (failure/denied/audit failure) nếu có.** — Predicate cmdline CONTAINS 'Logon Failed' trả 0; PEAK nói thất bại có thể nằm ở action/status, và local telemetry không có event_id 4625.
4. **Nếu we1149srv là public-facing, pivot sang nguồn web_request cùng host/domain/ip/time window để xác định traffic bên ngoài; chỉ dùng để tương quan thời điểm, không dùng để xác nhận logon failure.** — PEAK xác định web_request là nguồn phụ để nhận diện server public-facing và thời điểm tấn công.
5. **Kiểm tra process_creation và smb trong ±1 giờ quanh bất kỳ web_request hoặc authentication bất thường (nếu có) để tìm dấu hiệu đăng nhập thành công hoặc hậu khai thác.** — PEAK đề xuất pivot hậu burst sang process_creation và smb nếu nghi ngờ compromise sau brute force.

_Gợi ý bước tiếp theo do LLM tạo từ kế hoạch PEAK; chỉ mang tính tham khảo._

**Câu hỏi để người săn tự trả lời trước khi quyết định**

- Vì sao scope host là we1149srv? Ánh xạ từ able.location có đáng tin không, và có khả năng sai tên host so với source_hosts không?
- Danh sách source_hosts chỉ có we9748srv/we5364srv/we1864srv với tổng 400, trong khi source_rows_in_window là 20,657; danh sách đó là top hay đầy đủ?
- Nguồn authentication có trường action/status không? Nếu có, giá trị nào biểu thị thất bại?
- Có telemetry web_request cho we1149srv trong cửa sổ không? Có event_id 4625 hoặc nguồn failed logon nào khác không?
- Cửa sổ 28 ngày đầy đủ có sẵn không, hay chỉ có 2016-08-21?

**Rủi ro nếu quyết định sai**

- Bỏ sót brute force do scope host we1149srv không có bản ghi authentication; PoC chưa từng chạy trên host đó.
- Predicate literal cmdline CONTAINS 'Logon Failed' quá hẹp; nếu action/status không mã hóa thất bại và không có 4625, không thể xác nhận failed authentication.
- Cửa sổ hiện tại chỉ 1 ngày thay vì 28 ngày khuyến nghị, có thể bỏ lỡ burst.
- Event_id 4624 thường là thành công; dùng nó cho failed logon có thể sai ngữ nghĩa nếu không có trường bổ trợ.
- Không có mẫu/top_values/samples nên không thể phân biệt brute force, password spraying hay lỗi người dùng.

## Kế hoạch từ PEAK Assistant

Chi tiết: `peak_able.md` (bảng ABLE) và `peak_hunt_plan.md` (hunt plan).

- research: PoC references (PEAK researcher not requested)
- ABLE: PEAK able_table
- plan: PEAK hunt_planner + hunt_plan_critic

## Act: bản nháp phát hiện (SPL)

Trạng thái: **DRAFT** (chưa chạy trên Splunk thật).

```spl
search index="botsv1" match(cmdline, "(?i)Logon Failed") user="admin" earliest=1471737600 latest=1471824000
| table _time, host, user, image, cmdline, domain, file_path, action
```

## Chi phí và tái lập

- LLM (judge + advisor): 1 lần gọi, 7004 token. Các agent bên trong PEAK Assistant tự tạo client riêng nên chưa được đo.
- Thời gian chạy bước Execute (gồm lệnh gọi judge): 6.13s
- Ledger: `artifacts\runs\v2\poc-bruteforce-we1149srv\poc-bruteforce-we1149srv.json`
