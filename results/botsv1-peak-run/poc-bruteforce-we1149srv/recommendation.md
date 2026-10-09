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

1. **Kiểm tra lại toàn bộ telemetry authentication trong cửa sổ mở rộng (toàn bộ thời gian có sẵn) để tìm cmdline chứa 'Logon Failed' (không phân biệt hoa thường).** — Đảm bảo không bỏ lỡ do cửa sổ thời gian quá hẹp.
2. **Lọc sự kiện authentication có event_id = 4625 (nếu có) hoặc trường action/status chỉ ra thất bại, để xác thực các попытка đăng nhập thất bại mà không phụ thuộc vào chuỗi cmdline.** — Một số hệ thống ghi thất bại qua event_id hoặc trường trạng thái thay vì chuỗi cmdline.
3. **Thống kê số lượng sự kiện authentication thất bại theo host và user trong các khoảng thời gian ngắn (ví dụ 5 phút) để phát hiện bursts, bất kể nội dung cmdline.** — Brute force thường biểu hiện qua nhiều lần thất bại liên tiếp từ cùng host/user.
4. **Kiểm tra xem có trường hoặc thẻ nào chỉ ra host là public‑facing (ví dụ cổng DMZ, danh sách tài sản) trong telemetry hoặc tài sản bên ngoài; nếu không có, sử dụng danh sách host được cung cấp bởi quản trị để hạn chế tìm kiếm.** — Yếu tố location trong hypothesis cần xác định host tiếp xúc internet.
5. **Xác nhận rằng trường cmdline được điền đầy đủ và không bị truncate trong các bản ghi authentication; chạy truy vấn chọn một số mẫu cmdline để xem nội dung thực tế.** — Nếu trường cmdline trống hoặc không chứa chuỗi mong đợi, predicate sẽ luôn trả về 0.

_Gợi ý bước tiếp theo do LLM tạo từ kế hoạch PEAK; chỉ mang tính tham khảo._

**Câu hỏi để người săn tự trả lời trước khi quyết định**

- Có bất kỳ trường nào khác như status, action, hoặc event_id chỉ ra đăng nhập thất bại ngoài chuỗi 'Logon Failed' trong cmdline không?
- Dữ liệu telemetry có bao gồm danh sách tài sản hoặc thẻ đánh dấu host là public‑facing (DMZ, internet‑exposed) không?
- Có thể mở rộng cửa sổ thời gian ngoài 2016‑08‑21 → 2016‑08‑22 để xem xét thời gian dài hơn không?
- Ngoài bảng authentication, có bất kỳ nguồn log bảo mật nào khác (ví dụ Windows Security logs, VPN logs) được thu thập không?
- Trường cmdline trong các bản ghi authentication có thường được điền và có thể chứa các biến thể như 'failed logon', 'logon failure', 'authentication failed' không?

**Rủi ro nếu quyết định sai**

- Do không có trường hoặc thẻ xác định host public‑facing, hunt có thể bỏ qua các cuộc tấn công thực sự đối với máy chủ tiếp xúc internet hoặc báo falsa positive trên hệ thống nội bộ.
- Nếu chuỗi 'Logon Failed' không xuất hiện trong cmdline do định dạng log khác, predicate sẽ luôn trả về 0 dẫn tới false negative.
- Thiếu dữ liệu về reputations IP hoặc geo‑location làm hạn chế khả năng xác định nguồn tấn công độc hại.
- Cửa sổ thời gian được sử dụng trong lần chạy ban đầu có thể quá ngắn, không khớp với thời gian thực sự của cuộc tấn công.
- Sự phụ thuộc vào một trường duy nhất (cmdline) để xác định thất bại làm giảm độ bền của hunt nếu trường đó bị lỗi hoặc không được điền đầy đủ.

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

- LLM (judge + advisor): 1 lần gọi, 6629 token.
- Toàn bộ LLM (gồm các agent trong PEAK): 4 lần gọi, 21,546 token (12,017 vào / 9,529 ra).
- Model thực sự trả lời (cấu hình: `nvidia/nemotron-3-super-120b-a12b:free`): `nvidia/nemotron-3-super-120b-a12b:free` (4 lần)
- Cache Prepare: chạy mới và đã lưu.
- Judge: 3 lần gọi lấy đa số; temperature 0.0.
- Thời gian chạy bước Execute (gồm lệnh gọi judge): 4.87s
- Ledger: `artifacts\runs\full\poc-bruteforce-we1149srv\poc-bruteforce-we1149srv.json`
