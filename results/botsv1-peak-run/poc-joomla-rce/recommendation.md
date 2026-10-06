# Khuyến nghị hunt — `poc-joomla-rce`

**PoC:** Joomla RCE web compromise (BOTS v1 real attack)  
**Cửa sổ dữ liệu:** `2016-08-10T21:36:00Z/2016-08-10T22:00:00Z`  
**Nguồn dữ liệu:** CDB data/botsv1_eval.sqlite  
**PEAK Assistant:** đã dùng (ABLE + hunt plan)

## Khuyến nghị

### Chuyển IR (escalate)
`ESCALATE_TO_IR` — độ tin cậy **trung bình** (MEDIUM).

> Đây là gợi ý hỗ trợ quyết định. **Người săn mối đe dọa là người quyết định cuối cùng**; hệ thống không tự hành động.

**Lý do**

- 2/2 bước PoC có kết quả, tổng 200 bản ghi khớp.
- Khoảng thời gian hit: 2016-08-10T21:36:45Z → 2016-08-10T21:40:57Z.
- Judge (advisory) đánh giá TRUE_POSITIVE, độ tin cậy 0.85.
- Độ tin cậy bị hạ xuống MEDIUM: PoC không có bước nào kiểm tra kết quả (status/action) nên chưa chứng minh được tấn công thành công.

**Cần lưu ý (giới hạn của kết luận)**

- Khớp predicate literal chứng minh có hoạt động tương ứng trong dữ liệu; tự nó chưa chứng minh thành công hay tác động (cần xem response/status và hậu quả trên host).
- Bước `s1-victim-site`: chỉ hiển thị 100 bản ghi trong ít nhất 1999 bản ghi khớp (quét đã dừng ở giới hạn hàng nên tổng thực tế có thể lớn hơn).
- Bước `s2-joomla-path`: chỉ hiển thị 100 bản ghi trong ít nhất 2000 bản ghi khớp (quét đã dừng ở giới hạn hàng nên tổng thực tế có thể lớn hơn).

## Các lựa chọn cho người quyết định (xếp theo ưu tiên)

| # | Hành động | Việc cần làm |
|---|---|---|
| 1 | `ESCALATE_TO_IR` (Chuyển IR (escalate)) | Chuyển gói bằng chứng cho IR và giữ nguyên log gốc; trước khi cô lập, xác nhận vai trò thật của splunk-02 (nạn nhân, nguồn tấn công hay sensor ghi log). |
| 2 | `INVESTIGATE_FURTHER` (Điều tra sâu hơn) | Pivot theo splunk-02: xem process/network/auth cùng khoảng 2016-08-10T21:36:45Z; xác định bước nào của chuỗi còn thiếu bằng chứng. |
| 3 | `TUNE_POC_OR_CLOSE` (Tinh chỉnh PoC hoặc đóng (nghi false positive)) | Xem mẫu bản ghi, thêm điều kiện loại trừ hoạt động hợp lệ (parent, signer, tài khoản dịch vụ) rồi chạy lại; đóng nếu xác nhận là noise. |

## Bằng chứng

| Bước | Predicate | Nguồn | Bản ghi nguồn trong cửa sổ | Trong phạm vi lọc | Khớp (hiển thị / tổng) |
|---|---|---|---|---|---|
| `s1-victim-site` | `domain EQUALS imreallynotbatman.com` | web | 12,546 | 12,546 | 100 / ≥1999 |
| `s2-joomla-path` | `cmdline CONTAINS /joomla/` | web | 12,546 | 12,546 | 100 / ≥2000 |

Tổng 200 bản ghi hiển thị làm bằng chứng; 2/2 bước có kết quả.
Hit đầu tiên 2016-08-10T21:36:45Z, hit cuối 2016-08-10T21:40:57Z.
- Top `host`: splunk-02 (200)
- Top `ip`: 40.80.148.42 (200)
- Top `domain`: imreallynotbatman.com (200)
- Giá trị phổ biến của `domain`: `imreallynotbatman.com` (200)
- Giá trị phổ biến của `cmdline`: `site=imreallynotbatman.com uri=/joomla/index.php/component/search/` (15), `site=imreallynotbatman.com uri=/` (12), `site=imreallynotbatman.com uri=/joomla/index.php` (9)

**Mẫu bản ghi**

- `{'timestamp': '2016-08-10T21:36:45Z', 'host': 'splunk-02', 'cmdline': 'site=imreallynotbatman.com uri=/acunetix-wvs-test-for-some-inexistent-file', 'ip': '40.80.148.42', 'domain': 'imreallynotbatman.com'}`
- `{'timestamp': '2016-08-10T21:36:45Z', 'host': 'splunk-02', 'cmdline': 'site=imreallynotbatman.com uri=/', 'ip': '40.80.148.42', 'domain': 'imreallynotbatman.com'}`
- `{'timestamp': '2016-08-10T21:36:48Z', 'host': 'splunk-02', 'cmdline': 'site=imreallynotbatman.com uri=/PdgdyH6M', 'ip': '40.80.148.42', 'domain': 'imreallynotbatman.com'}`

## Judge (LLM, chỉ tham khảo)

**TRUE_POSITIVE** — độ tin cậy 0.85

Requests to /acunetix-wvs-test-for-some-inexistent-file and random 8-character URIs followed by Joomla component enumeration (/joomla/components/com_jnews/..., /joomla/index.php...) within a tight 21:36-21:40 window match automated Joomla vulnerability scanning/exploitation activity from the BOTS v1 real attack, not routine user traffic.
- Acunetix scanner signature and randomized paths indicate automated reconnaissance.
- Joomla component paths align with the PoC's Joomla RCE compromise hypothesis.
- No change-ticket or sanctioned-scan metadata is present in the provided rows.

## Gợi ý bước tiếp theo (từ kế hoạch PEAK, LLM)

1. **Truy vấn web_request trong cửa sổ 2016-08-10T21:36:00Z–22:00:00Z, lọc domain EQUALS imreallynotbatman.com, nhóm theo action và status; nếu trường action/status không có hoặc rỗng, ghi nhận là telemetry thiếu.** — Bước PoC chưa kiểm tra status/action nên chưa biết request nào thành công; cần xác định 200/302/403/404/500 để đánh giá khả năng khai thác.
2. **Lấy đầy đủ các bản ghi khớp cho hai bước s1-victim-site và s2-joomla-path (matched_total khoảng 1999–2000 nhưng row_count 100, scan_truncated=true) bằng phân trang hoặc nới ngưỡng.** — Dữ liệu bị cắt nên mới thấy 200/2000 bản ghi; cần xem toàn bộ URI, IP, timestamp để tìm payload search/mailto và mẫu bất thường.
3. **Kiểm tra process_creation trên host splunk-02 trong và sau cửa sổ 21:36–21:40, event_id 4688 hoặc 1, tìm tiến trình con bất thường, cmdline lạ, image ngoài tiến trình web.** — RCE thành công thường tạo process_creation trên web server; đây là mắt xích còn thiếu để nâng độ tin cậy.
4. **Truy vấn web_request với domain EQUALS imreallynotbatman.com và cmdline CONTAINS search hoặc cmdline CONTAINS mailto trong cùng cửa sổ; nhóm theo ip, cmdline, action, status.** — Giả thuyết nêu Joomla search/mailto; cần tách hai thành phần này khỏi các đường dẫn Joomla hợp lệ khác.
5. **Pivot IP 40.80.148.42 sang các nguồn web_request, authentication, dns, smb trong cùng ngày 2016-08-10 để xem còn tương tác ngoài imreallynotbatman.com hoặc dấu hiệu C2/lateral movement.** — Một IP nguồn chiếm toàn bộ 200 bản ghi; cần xác định phạm vi hoạt động và hậu quả sau khai thác.

_Gợi ý bước tiếp theo do LLM tạo từ kế hoạch PEAK; chỉ mang tính tham khảo._

**Câu hỏi để người săn tự trả lời trước khi quyết định**

- Trường action và status trong web_request có giá trị cụ thể nào cho các bản ghi đã khớp, và có request POST hoặc payload search/mailto nào không?
- Có telemetry process_creation (4688/1) trên splunk-02 trong khoảng 21:36–22:00 ngày 2016-08-10 không, và có tiến trình con nào đáng ngờ?
- Vì sao matched_total khoảng 1999–2000 nhưng row_count chỉ 100 và scan_truncated=true; có thể lấy đủ dữ liệu không?
- Có log WAF, web server access log, hoặc EDR bổ sung để xác nhận exploit thành công hay không?
- IP 40.80.148.42 có phải external/attacker hay là scanner/proxy dùng chung, và có hoạt động khác trong ngày không?

**Rủi ro nếu quyết định sai**

- Nhiều đường dẫn /joomla/ có thể là truy cập hợp lệ; cmdline CONTAINS /joomla/ có thể khớp nhầm, làm tăng false positive.
- Không có kiểm tra status/action trong PoC nên chưa chứng minh được khai thác thành công; confidence chỉ MEDIUM.
- Dữ liệu bị cắt (scan_truncated) nên bằng chứng chưa đầy đủ, có thể bỏ sót request quan trọng hoặc payload.
- Thiếu process_creation/EDR/WAF/web server log để xác nhận RCE, hậu khai thác, hoặc exfiltration.
- Cửa sổ hit ngắn (21:36:45–21:40:57) có thể chỉ là giai đoạn scan ban đầu, chưa thấy toàn bộ chuỗi tấn công.

## Kế hoạch từ PEAK Assistant

Chi tiết: `peak_able.md` (bảng ABLE) và `peak_hunt_plan.md` (hunt plan).

- research: PoC references (PEAK researcher not requested)
- ABLE: PEAK able_table
- plan: PEAK hunt_planner + hunt_plan_critic

## Act: bản nháp phát hiện (SPL)

Trạng thái: **DRAFT** (chưa chạy trên Splunk thật).

```spl
search index="botsv1" domain="imreallynotbatman.com" match(cmdline, "(?i)/joomla/") earliest=1470864960 latest=1470866400
| table _time, host, user, image, cmdline, domain, file_path, action
```

## Chi phí và tái lập

- LLM (judge + advisor): 2 lần gọi, 9524 token. Các agent bên trong PEAK Assistant tự tạo client riêng nên chưa được đo.
- Thời gian chạy bước Execute (gồm lệnh gọi judge): 16.09s
- Ledger: `artifacts\runs\v2\poc-joomla-rce\poc-joomla-rce.json`
