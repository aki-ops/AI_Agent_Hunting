# Khuyến nghị hunt — `poc-c2-beacon-networkfilter`

**PoC:** C2 beacon to ad.networkfilter.co (BOTS v1 known IOC)  
**Cửa sổ dữ liệu:** `2016-08-21T00:00:00Z/2016-08-22T00:00:00Z`  
**Nguồn dữ liệu:** CDB data/botsv1_eval.sqlite  
**PEAK Assistant:** đã dùng (ABLE + hunt plan)

## Khuyến nghị

### Đóng, kèm cảnh báo giới hạn
`CLOSE_WITH_CAVEAT` — độ tin cậy **trung bình** (MEDIUM).

> Đây là gợi ý hỗ trợ quyết định. **Người săn mối đe dọa là người quyết định cuối cùng**; hệ thống không tự hành động.

**Lý do**

- Không có bản ghi nào khớp bất kỳ bước nào của PoC trong cửa sổ đã chạy.
- Nguồn `web` có 566 bản ghi trong cửa sổ nhưng 0 bản ghi của host `we1149srv` (host lọc suy ra từ `able.location`); host thực sự ghi nguồn này: splunk-02 (566).
- Chạy lại cùng PoC KHÔNG lọc host: 0 bản ghi khớp ở bất kỳ host nào trong cửa sổ. Dữ liệu hiện có không chứa dấu hiệu này ở đâu cả, nhưng phát hiện này chỉ đúng với predicate literal, loại sự kiện đang có và cửa sổ đã quét; host nêu trong PoC không hề ghi nguồn này nên PoC chưa từng được thử trên host đó.

**Cần lưu ý (giới hạn của kết luận)**

- Nguồn có dữ liệu chưa chắc chứa đúng loại sự kiện cần tìm (ví dụ chỉ có đăng nhập thành công, không có đăng nhập thất bại); hệ thống chưa tự đối chiếu với predicate.
- Loại sự kiện của nguồn `web` trong cửa sổ (mọi host): web_request (566). Hãy xác nhận loại sự kiện mà PoC cần (ví dụ đăng nhập thất bại 4625) có trong danh sách này.
- PoC chỉ kiểm tra các predicate literal đã khai báo; biến thể (obfuscation, tên khác, field khác) không được thử.
- Chỉ quét cửa sổ 2016-08-21T00:00:00Z/2016-08-22T00:00:00Z; hoạt động ngoài cửa sổ không được xem.
- Ngoài predicate của từng bước, truy vấn còn bị giới hạn bởi các điều kiện suy ra từ ABLE của PoC: host = `we1149srv`.

## Các lựa chọn cho người quyết định (xếp theo ưu tiên)

| # | Hành động | Việc cần làm |
|---|---|---|
| 1 | `CLOSE_WITH_CAVEAT` (Đóng, kèm cảnh báo giới hạn) | Đóng hunt, ghi rõ giới hạn; cân nhắc mở rộng cửa sổ hoặc biến thể predicate trước khi coi là sạch. |
| 2 | `COLLECT_DATA_THEN_RERUN` (Bổ sung telemetry rồi chạy lại) | Kiểm tra phạm vi host của PoC (`we1149srv`): nguồn web có dữ liệu nhưng ở host khác; sửa `able.location` hoặc bổ sung telemetry của host đó rồi chạy lại. |

## Bằng chứng

| Bước | Predicate | Nguồn | Bản ghi nguồn trong cửa sổ | Trong phạm vi lọc | Khớp (hiển thị / tổng) |
|---|---|---|---|---|---|
| `s1-c2-domain` | `cmdline CONTAINS ad.networkfilter.co` | web | 566 | 0 | 0 |
| `s2-c2-banner` | `cmdline CONTAINS /banner/` | web | 566 | 0 | 0 |

**Phạm vi truy vấn thực tế** (ngoài predicate, suy ra từ ABLE của PoC):
- host = `we1149srv`

Tổng 0 bản ghi hiển thị làm bằng chứng; 0/2 bước có kết quả.

## Judge (LLM, chỉ tham khảo)

**NO_SIGNAL** — độ tin cậy 0.00

No adapter hits and no escalation evidence; result is 'absence of evidence', not 'evidence of absence'.
- skipped_llm

## Gợi ý bước tiếp theo (từ kế hoạch PEAK, LLM)

1. **Kiểm tra toàn bộ sự kiện web_request trong cửa sổ để xác nhận có bất kỳ bản ghi nào chứa domain ad.networkfilter.co (không lọc host)** — Đảm bảo rằng việc không có kết quả không do lỗi lọc host hoặc predicate.
2. **Kiểm tra sự kiện web_request cho cmdline chứa '/banner/' trong toàn bộ cửa sổ (không lọc host)** — Xác nhận xem mẫu URI đặc trưng của BOTS v1 có xuất hiện nào không.
3. **Kiểm tra sự kiện dns cho các truy vấn domain chứa ad.networkfilter.co trong cửa sổ** — DNS lookup có thể xảy ra trước HTTP request; nếu không có, giảm khả năng beacon.
4. **Kiểm tra sự kiện process_creation (event_id 4688 hoặc 1) để tìm các tiến trình có khả năng thực hiện yêu cầu HTTP outbound (ví dụ: image có chứa 'curl', 'wget', 'powershell', 'bitsadmin') trong cửa sổ** — Nếu không có web request, có thể beacon được thực hiện qua các công cụ khác; kiểm tra để tìm dấu hiệu thực thi.
5. **Xác nhận tính đầy đủ của nguồn telemetry web: đếm tổng số bản ghi web_request trong cửa sổ và so sánh với tổng số bản ghi được báo cáo (566) để chắc chắn không có mất dữ liệu** — Đảm bảo rằng telemetry web thực sự tồn tại và đủ để thực hiện hunt.

_Gợi ý bước tiếp theo do LLM tạo từ kế hoạch PEAK; chỉ mang tính tham khảo._

**Câu hỏi để người săn tự trả lời trước khi quyết định**

- Có bất kỳ sự kiện web_request nào trong cửa sổ có trường domain hoặc cmdline chứa chuỗi 'ad.networkfilter.co' không?
- Có sự kiện dns nào cho domain ad.networkfilter.co trong cửa sổ không?
- Có sự kiện process_creation nào liên quan đến các công cụ thường dùng để thực hiện HTTP outbound (curl, wget, powershell, bitsadmin) trong cửa sổ không?

**Rủi ro nếu quyết định sai**

- Giả âm positif: việc không tìm thấy dấu hiệu có thể do telemetry bị thiếu hoặc không ghi lại các kết nối outbound.
- Giả âm dương: nếu có beacon nhưng sử dụng mã hóa hoặc các cổng không chuẩn (không phải HTTP) thì hunt dựa trên web_request sẽ không phát hiện.
- Rủi ro về thời gian: cửa sổ hiện tại (2016-08-21 đến 2016-08-22) có thể không chứa hoạt động beacon nếu nó xảy ra ngoài khoảng thời gian này.

## Kế hoạch từ PEAK Assistant

Chi tiết: `peak_able.md` (bảng ABLE) và `peak_hunt_plan.md` (hunt plan).

- research: PoC references (PEAK researcher not requested)
- ABLE: PEAK able_table
- plan: PEAK hunt_planner + hunt_plan_critic

## Act: bản nháp phát hiện (SPL)

Trạng thái: **DRAFT** (chưa chạy trên Splunk thật).

```spl
search index="botsv1" match(cmdline, "(?i)ad.networkfilter.co") match(cmdline, "(?i)/banner/") earliest=1471737600 latest=1471824000
| table _time, host, user, image, cmdline, domain, file_path, action
```

## Chi phí và tái lập

- LLM (judge + advisor): 1 lần gọi, 4637 token.
- Toàn bộ LLM (gồm các agent trong PEAK): 4 lần gọi, 18,292 token (12,904 vào / 5,388 ra).
- Model thực sự trả lời (cấu hình: `nvidia/nemotron-3-super-120b-a12b:free`): `nvidia/nemotron-3-super-120b-a12b:free` (4 lần)
- Cache Prepare: chạy mới và đã lưu.
- Judge: 3 lần gọi lấy đa số; temperature 0.0.
- Thời gian chạy bước Execute (gồm lệnh gọi judge): 4.95s
- Ledger: `artifacts\runs\full\poc-c2-beacon-networkfilter\poc-c2-beacon-networkfilter.json`
