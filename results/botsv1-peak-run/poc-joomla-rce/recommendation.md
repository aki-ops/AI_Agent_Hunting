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

- 2/2 bước PoC có kết quả, tổng 199 bản ghi khớp.
- Khoảng thời gian hit: 2016-08-10T21:36:45Z → 2016-08-10T21:40:57Z.
- Judge (advisory) đánh giá TRUE_POSITIVE, độ tin cậy 0.88.
- Độ tin cậy bị hạ xuống MEDIUM: PoC không có bước nào kiểm tra kết quả (status/action) nên chưa chứng minh được tấn công thành công.

**Cần lưu ý (giới hạn của kết luận)**

- Khớp predicate literal chứng minh có hoạt động tương ứng trong dữ liệu; tự nó chưa chứng minh thành công hay tác động (cần xem response/status và hậu quả trên host).

## Các lựa chọn cho người quyết định (xếp theo ưu tiên)

| # | Hành động | Việc cần làm |
|---|---|---|
| 1 | `ESCALATE_TO_IR` (Chuyển IR (escalate)) | Chuyển gói bằng chứng cho IR và giữ nguyên log gốc; trước khi cô lập, xác nhận vai trò thật của splunk-02 (nạn nhân, nguồn tấn công hay sensor ghi log). |
| 2 | `INVESTIGATE_FURTHER` (Điều tra sâu hơn) | Pivot theo splunk-02: xem process/network/auth cùng khoảng 2016-08-10T21:36:45Z; xác định bước nào của chuỗi còn thiếu bằng chứng. |
| 3 | `TUNE_POC_OR_CLOSE` (Tinh chỉnh PoC hoặc đóng (nghi false positive)) | Xem mẫu bản ghi, thêm điều kiện loại trừ hoạt động hợp lệ (parent, signer, tài khoản dịch vụ) rồi chạy lại; đóng nếu xác nhận là noise. |

## Bằng chứng

| Bước | Predicate | Nguồn | Bản ghi nguồn trong cửa sổ | Khớp |
|---|---|---|---|---|
| `s1-victim-site` | `domain EQUALS imreallynotbatman.com` | web | 12,546 | 99 |
| `s2-joomla-path` | `cmdline CONTAINS /joomla/` | web | 12,546 | 100 |

Tổng 199 bản ghi khớp; 2/2 bước có kết quả.
Hit đầu tiên 2016-08-10T21:36:45Z, hit cuối 2016-08-10T21:40:57Z.
- Top `host`: splunk-02 (199)
- Top `ip`: 40.80.148.42 (199)
- Top `domain`: imreallynotbatman.com (199)
- Giá trị phổ biến của `domain`: `imreallynotbatman.com` (199)
- Giá trị phổ biến của `cmdline`: `site=imreallynotbatman.com uri=/joomla/index.php/component/search/` (15), `site=imreallynotbatman.com uri=/` (12), `site=imreallynotbatman.com uri=/joomla/index.php` (9)

**Mẫu bản ghi**

- `{'timestamp': '2016-08-10T21:36:45Z', 'host': 'splunk-02', 'cmdline': 'site=imreallynotbatman.com uri=/acunetix-wvs-test-for-some-inexistent-file', 'ip': '40.80.148.42', 'domain': 'imreallynotbatman.com'}`
- `{'timestamp': '2016-08-10T21:36:45Z', 'host': 'splunk-02', 'cmdline': 'site=imreallynotbatman.com uri=/', 'ip': '40.80.148.42', 'domain': 'imreallynotbatman.com'}`
- `{'timestamp': '2016-08-10T21:36:48Z', 'host': 'splunk-02', 'cmdline': 'site=imreallynotbatman.com uri=/PdgdyH6M', 'ip': '40.80.148.42', 'domain': 'imreallynotbatman.com'}`

## Judge (LLM, chỉ tham khảo)

**TRUE_POSITIVE** — độ tin cậy 0.88

Evidence shows reconnaissance and Joomla component probing against imreallynotbatman.com within the PoC window: Acunetix scanner test URI, random 8-character paths, and direct access to /joomla/ component paths including open-flash-chart.swf. This is consistent with the described Joomla RCE web compromise attack chain rather than normal browsing or baseline operations.
- Acunetix WVS test file indicates automated vulnerability scanning.
- Random paths and Joomla component enumeration suggest exploit reconnaissance.
- Target domain matches the PoC victim site.

## Gợi ý bước tiếp theo (từ kế hoạch PEAK, LLM)

1. **Truy vấn process_creation trên host splunk-02 trong cửa sổ 2016-08-10T21:36:00Z–22:00:00Z, lọc image/cmdline bất thường (cmd.exe, powershell, wget, curl, /bin/sh) để tìm dấu hiệu RCE.** — 
2. **Kiểm tra trường status/action của web_request cho các URI chứa /joomla/ (đặc biệt component/search) để xác định mã HTTP 200 vs 404/500; nếu trường trống, ghi nhận thiếu telemetry.** — 
3. **Pivot authentication: tìm sự kiện đăng nhập (4624) từ IP 40.80.148.42 hoặc trên host splunk-02 trong cùng khung giờ.** — 
4. **Pivot DNS: tìm truy vấn DNS từ host splunk-02 ra domain lạ trong 2016-08-10 21:36–22:00.** — 
5. **Tìm trong cmdline web_request các chuỗi com_search, com_mailto, hoặc dấu hiệu exploit (base64, cmd=, eval) để phân biệt scan và khai thác.** — 

_Gợi ý bước tiếp theo do LLM tạo từ kế hoạch PEAK; chỉ mang tính tham khảo._

**Câu hỏi để người săn tự trả lời trước khi quyết định**

- Có bản ghi process_creation nào trên splunk-02 trong khoảng 21:36–22:00 ngày 2016-08-10 không?
- Mã trạng thái HTTP của các request /joomla/index.php/component/search/ là gì?
- Có sự kiện authentication nào từ 40.80.148.42 hoặc user bất thường trên splunk-02 không?
- Có truy vấn DNS hoặc kết nối SMB ra ngoài từ splunk-02 trong cùng khung giờ không?
- Có bằng chứng nào cho thấy 40.80.148.42 là scanner hợp pháp (Acunetix) hay là kẻ tấn công thực sự?

**Rủi ro nếu quyết định sai**

- Chưa có bước kiểm tra status/action nên chưa chứng minh RCE thành công; có thể chỉ là scan.
- Mẫu có /acunetix-wvs-test-for-some-inexistent-file gợi ý scanner Acunetix, có thể dương tính giả.
- Telemetry process_creation có thể thưa hoặc thiếu, không đủ kết luận.
- Sự kiện chỉ thấy từ một IP 40.80.148.42; nếu không kiểm tra IP khác có thể bỏ sót.
- Việc escalate lên IR khi chưa xác nhận thành công có thể gây lãng phí nguồn lực.

## Kế hoạch từ PEAK Assistant

Chi tiết: `peak_able.md` (bảng ABLE) và `peak_hunt_plan.md` (hunt plan).

- research: PoC references (PEAK researcher not requested)
- ABLE: PEAK able_table
- plan: PEAK hunt_planner + hunt_plan_critic

## Act: bản nháp phát hiện (SPL)

Trạng thái: **DRAFT** (chưa chạy trên Splunk thật).

```spl
search index="botsv1" domain="imreallynotbatman.com" match(cmdline, "(?i)/joomla/") earliest=-14d latest=now
| table _time, host, user, image, cmdline, domain, file_path, action
```

## Chi phí và tái lập

- LLM (judge + advisor): 2 lần gọi, 7393 token. Các agent bên trong PEAK Assistant tự tạo client riêng nên chưa được đo.
- Thời gian chạy bước Execute (gồm lệnh gọi judge): 6.23s
- Ledger: `artifacts\runs\auto\poc-joomla-rce\poc-joomla-rce.json`
