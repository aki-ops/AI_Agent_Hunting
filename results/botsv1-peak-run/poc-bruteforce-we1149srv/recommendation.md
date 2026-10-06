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
- Các nguồn telemetry cần thiết có dữ liệu trong cửa sổ nhưng predicate không khớp.

**Cần lưu ý (giới hạn của kết luận)**

- Nguồn có dữ liệu chưa chắc chứa đúng loại sự kiện cần tìm (ví dụ chỉ có đăng nhập thành công, không có đăng nhập thất bại); hệ thống chưa xác minh điều này.
- PoC chỉ kiểm tra các predicate literal đã khai báo; biến thể (obfuscation, tên khác, field khác) không được thử.
- Chỉ quét cửa sổ 2016-08-21T00:00:00Z/2016-08-22T00:00:00Z; hoạt động ngoài cửa sổ không được xem.

## Các lựa chọn cho người quyết định (xếp theo ưu tiên)

| # | Hành động | Việc cần làm |
|---|---|---|
| 1 | `CLOSE_WITH_CAVEAT` (Đóng, kèm cảnh báo giới hạn) | Đóng hunt, ghi rõ giới hạn; cân nhắc mở rộng cửa sổ hoặc biến thể predicate trước khi coi là sạch. |
| 2 | `COLLECT_DATA_THEN_RERUN` (Bổ sung telemetry rồi chạy lại) | Nguồn đã có dữ liệu; chỉ cần nếu muốn bổ sung loại telemetry khác (vd. sysmon, network flow) để bắt biến thể ngoài predicate. |

## Bằng chứng

| Bước | Predicate | Nguồn | Bản ghi nguồn trong cửa sổ | Khớp |
|---|---|---|---|---|
| `s1-failed-auth` | `cmdline CONTAINS Logon Failed` | authentication | 20,657 | 0 |
| `s2-targeted-user` | `user EQUALS admin` | authentication | 20,657 | 0 |

Tổng 0 bản ghi khớp; 0/2 bước có kết quả.

## Judge (LLM, chỉ tham khảo)

**NO_SIGNAL** — độ tin cậy 0.00

No adapter hits and no escalation evidence; result is 'absence of evidence', not 'evidence of absence'.
- skipped_llm

## Gợi ý bước tiếp theo (từ kế hoạch PEAK, LLM)

1. **Mở rộng cửa sổ truy vấn ra toàn bộ 2016-08-01 đến 2016-08-28 và chạy lại các vị từ native_type EQUALS authentication, event_id EQUALS 4624, cmdline CONTAINS Logon Failed** — Cửa sổ đã chạy 2016-08-21 đến 2016-08-22 chỉ có 20657 dòng authentication trong khi kế hoạch ghi nhận 579580 dòng trên 28 ngày, nên 0 khớp có thể do giới hạn thời gian
2. **Pivot giá trị distinct của action và status trên tập native_type EQUALS authentication để xác minh mã hóa kết quả đăng nhập** — Cả hai vị từ cmdline CONTAINS Logon Failed và user EQUALS admin đều trả về 0 dù nguồn có dữ liệu, cần kiểm tra outcome còn phản ánh ở action và status hay không
3. **Pivot group và count theo host, user, ip và timestamp binned theo giờ và 5 phút trên tập authentication** — Theo kế hoạch PEAK, bằng chứng burst yêu cầu chứng minh nhiều thất bại tới cùng host và user và ip trong cửa sổ thời gian nén, chưa được định lượng
4. **Kiểm tra cmdline CONTAINS Logon Success và pivot theo cùng host, user, ip, timestamp để đối chiếu thành công sau burst** — Kế hoạch yêu cầu kiểm tra thỏa hiệp bằng mẫu Logon Success user=.. ip=.. trong cmdline, giúp phân biệt quét thất bại và đăng nhập thành công
5. **Pivot top user trên tập authentication thay vì chỉ giới hạn user EQUALS admin** — Theo ghi chú PEAK, user EQUALS admin chỉ là ví dụ mục tiêu đặc quyền do analyst tự đặt, brute force có thể nhắm các tài khoản khác

_Gợi ý bước tiếp theo do LLM tạo từ kế hoạch PEAK; chỉ mang tính tham khảo._

**Câu hỏi để người săn tự trả lời trước khi quyết định**

- Ngưỡng burst bao nhiêu sự kiện trên cùng host, user, ip trong bao nhiêu phút được coi là brute force để kết luận?
- Có inventory tài sản hoặc zone mapping nào xác nhận host tập trung xác thực là máy chủ public-facing hay không?
- Có muốn hunt toàn bộ 28 ngày tháng 08-2016 trước khi đóng hay chỉ giới hạn ở cửa sổ 21-22/08/2016?
- Kết quả xác thực có được mã hóa chuẩn ở action và status ngoài cmdline hay không?
- Có cần loại trừ các nguồn native_type process_creation, smb, web_request, dns khỏi phạm vi hunt này không?

**Rủi ro nếu quyết định sai**

- Đóng với cảnh báo khi mới hunt 1 ngày có thể bỏ sót burst brute force ở 27 ngày còn lại của tháng 08-2016
- Predicate cmdline không khớp có thể do diễn giải sai mã hóa, dẫn tới âm tính giả nếu chỉ dựa vào chuỗi Logon Failed
- Chỉ tập trung user admin có thể bỏ sót brute force nhắm tài khoản khác
- Thiếu inventory khiến không thể chứng minh host là public-facing theo giả thuyết
- Thiếu ngưỡng burst định nghĩa trước khiến khó phân biệt burst tấn công với baseline xác thực cao

## Kế hoạch từ PEAK Assistant

Chi tiết: `peak_able.md` (bảng ABLE) và `peak_hunt_plan.md` (hunt plan).

- PEAK Prepare attempt 1/2 failed (Exception: An error occurred while planning the hunt.)
- research: PoC references (PEAK researcher not requested)
- ABLE: PEAK able_table
- plan: PEAK hunt_planner + hunt_plan_critic

## Act: bản nháp phát hiện (SPL)

Trạng thái: **DRAFT** (chưa chạy trên Splunk thật).

```spl
search index="botsv1" match(cmdline, "(?i)Logon Failed") user="admin" earliest=-14d latest=now
| table _time, host, user, image, cmdline, domain, file_path, action
```

## Chi phí và tái lập

- LLM (judge + advisor): 1 lần gọi, 4095 token. Các agent bên trong PEAK Assistant tự tạo client riêng nên chưa được đo.
- Thời gian chạy bước Execute (gồm lệnh gọi judge): 2.98s
- Ledger: `artifacts\runs\final\poc-bruteforce-we1149srv\poc-bruteforce-we1149srv.json`
