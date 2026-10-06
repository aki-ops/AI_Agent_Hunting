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
- Judge (advisory) đánh giá TRUE_POSITIVE, độ tin cậy 0.85.
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

**TRUE_POSITIVE** — độ tin cậy 0.85

21:36-21:40Z burst to imreallynotbatman.com includes /acunetix-wvs-test-for-some-inexistent-file, random fuzz /PdgdyH6M /OD6xDhbF, and /joomla/components/com_jnews/.../open-flash-chart.swf plus /joomla/ enumeration, matching PoC Joomla scan phase and inconsistent with normal browsing.
- Acunetix probe is scanner-only, never benign user traffic
- 199 observations in 24min indicates sustained enumeration
- Vulnerable Joomla component probing aligns with RCE prep

## Gợi ý bước tiếp theo (từ kế hoạch PEAK, LLM)

(không có)

_Advisor LLM lỗi (NotFoundError): không có gợi ý bổ sung._

**Câu hỏi để người săn tự trả lời trước khi quyết định**

- (không có)

**Rủi ro nếu quyết định sai**

- (không có)

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

- LLM (judge + advisor): 1 lần gọi, 3330 token. Các agent bên trong PEAK Assistant tự tạo client riêng nên chưa được đo.
- Thời gian chạy bước Execute (gồm lệnh gọi judge): 31.75s
- Ledger: `artifacts\runs\final\poc-joomla-rce\poc-joomla-rce.json`
