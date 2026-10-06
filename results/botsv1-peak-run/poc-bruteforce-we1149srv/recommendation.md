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

1. **Mở rộng truy vấn sang toàn bộ cửa sổ CDB 2016-08-01T00:00:00Z đến 2016-08-28T23:59:00Z; lọc native_type EQUALS authentication; nhóm theo host, user, ip, timestamp với bin 5 phút và 1 giờ.** — PEAK khuyến nghị 28 ngày và burst 5 phút/1 giờ; cửa sổ hiện tại 21-22 chỉ có 20,657 dòng auth nhưng không match, cần kiểm tra hành vi ngoài cửa sổ.
2. **Trong native_type EQUALS authentication, thống kê count theo action và status (và event_id) cho cùng cửa sổ.** — Predicate cmdline CONTAINS Logon Failed trả 0 dù có dữ liệu auth; cần xác nhận failure có được mã hóa ở action/status hay không.
3. **Pivot native_type EQUALS authentication theo user, host, ip; kiểm tra riêng user EQUALS admin và các tài khoản đặc quyền thực tế nếu có inventory.** — Bước s2 trả 0; cần biết tài khoản nào bị target thay vì chỉ giả định admin.
4. **Tìm cmdline CONTAINS Logon Success trong native_type EQUALS authentication, đối chiếu cùng host/user/ip và khoảng thời gian gần các failed tiềm năng.** — Chain chưa hoàn tất; cần kiểm tra thất bại có dẫn tới thành công sau đó không.
5. **Đối chiếu host trong authentication với web_request theo domain và cmdline chứa site=<host> uri=<path>; nếu không có, ghi nhận thiếu asset inventory/exposure.** — PEAK nêu public-facing không chứng minh được từ cột hiện có; cần web telemetry hoặc inventory để xác nhận Location.

_Gợi ý bước tiếp theo do LLM tạo từ kế hoạch PEAK; chỉ mang tính tham khảo._

**Câu hỏi để người săn tự trả lời trước khi quyết định**

- Có bản ghi authentication nào thể hiện thất bại qua action hoặc status nhưng không dùng chuỗi Logon Failed không?
- Tên tài khoản đặc quyền thực tế trên các host liên quan là gì, ngoài admin, và có inventory để xác nhận không?
- Host nào trong authentication cũng xuất hiện trong web_request hoặc có bằng chứng public-facing từ asset inventory?
- Có success event nào trên cùng host, user, ip gần các failed tiềm năng trong cửa sổ 21-22 hoặc cửa sổ rộng hơn không?
- Cửa sổ 2016-08-21 đến 2016-08-22 được chọn vì lý do gì, và có cần ưu tiên 28 ngày theo PEAK không?

**Rủi ro nếu quyết định sai**

- CLOSE_WITH_CAVEAT có thể bỏ sót brute force nếu failure được mã hóa khác Logon Failed trong cmdline, action hoặc status.
- Không thể xác nhận máy chủ public-facing chỉ từ dữ liệu authentication; thiếu asset inventory/exposure.
- Chỉ kiểm tra user EQUALS admin có thể bỏ sót tài khoản đặc quyền khác hoặc tài khoản bị target.
- Cửa sổ 21-22 hẹp hơn khuyến nghị 28 ngày của PEAK, nên có thể bỏ lỡ burst ngoài cửa sổ.
- Không có samples, top_values, pivots, first_seen, last_seen nên khó kiểm chứng nguồn IP, mẫu cmdline và pattern tấn công.

## Kế hoạch từ PEAK Assistant

Chi tiết: `peak_able.md` (bảng ABLE) và `peak_hunt_plan.md` (hunt plan).

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

- LLM (judge + advisor): 1 lần gọi, 6003 token. Các agent bên trong PEAK Assistant tự tạo client riêng nên chưa được đo.
- Thời gian chạy bước Execute (gồm lệnh gọi judge): 4.32s
- Ledger: `artifacts\runs\auto\poc-bruteforce-we1149srv\poc-bruteforce-we1149srv.json`
