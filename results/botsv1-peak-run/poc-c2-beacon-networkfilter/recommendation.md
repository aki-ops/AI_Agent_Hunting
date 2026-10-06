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

1. **Mở rộng cửa sổ quét từ 2016-08-21T00:00:00Z/2016-08-22T00:00:00Z lên toàn bộ dataset cục bộ 2016-08-01T00:00:00Z–2016-08-28T23:59:00Z, rồi chạy lại các predicate trực tiếp trên nguồn `web_request`: `domain EQUALS ad.networkfilter.co`, `cmdline CONTAINS ad.networkfilter.co`, `cmdline CONTAINS /banner/`, `cmdline CONTAINS site=ad.networkfilter.co`, không lọc host.** — 
2. **Chạy predicate `native_type EQUALS process_creation` và `cmdline CONTAINS ad.networkfilter.co` trên cùng cửa sổ mở rộng, mọi host, vì đây là nguồn hỗ trợ nếu URL/host xuất hiện trong dòng lệnh tiến trình.** — 
3. **Kiểm tra phân bố host của nguồn `web`: đếm `web_request` theo `host` trong cửa sổ mở rộng, xác nhận `we1149srv` có bản ghi nào không và làm rõ vì sao `splunk-02` giữ 566 bản ghi thay vì host đích.** — 
4. **Nếu giao với cửa sổ DNS 2016-08-24T10:25:02Z–16:34:35Z, chạy `native_type EQUALS dns` + `domain EQUALS ad.networkfilter.co`; ngoài khoảng này không thể xác nhận phân giải DNS.** — 
5. **Xác minh ngữ nghĩa trường `ip` và `port` trên `web_request` (client/source so với server/destination) trước khi pivot egress; nếu không xác định được, đánh dấu telemetry thiếu.** — 

_Gợi ý bước tiếp theo do LLM tạo từ kế hoạch PEAK; chỉ mang tính tham khảo._

**Câu hỏi để người săn tự trả lời trước khi quyết định**

- Cửa sổ đã chạy có bị giới hạn ở 2016-08-21/2016-08-22 thay vì toàn bộ 2016-08-01–2016-08-28 không, và vì sao?
- Vì sao nguồn `web` trong cửa sổ chỉ có host `splunk-02` với 566 bản ghi, còn host đích `we1149srv` có 0 bản ghi? Đây là do forwarder, scope sai hay host đó không ghi `web_request`?
- Các predicate `domain EQUALS ad.networkfilter.co` và `cmdline CONTAINS site=ad.networkfilter.co` đã được chạy chưa? EVIDENCE SUMMARY chỉ thấy hai bước `cmdline CONTAINS`.
- Nguồn nào sẽ cung cấp `web_request` cho `we1149srv` nếu host đó thực sự cần kiểm tra, và có bản ghi nào ngoài `splunk-02` không?
- Dữ liệu `dns` chỉ có trong 2016-08-24T10:25:02Z–16:34:35Z; có cần ưu tiên kiểm tra chồng lấn này không?

**Rủi ro nếu quyết định sai**

- Kết luận âm tính có thể sai do scope host rỗng: host `we1149srv` không có bản ghi `web` trong cửa sổ, nên PoC chưa từng được thử trên host đó theo nghĩa telemetry.
- Cửa sổ quét một ngày không đại diện toàn bộ dataset 2016-08-01–2016-08-28; beacon có thể nằm ngoài ngày 2016-08-21/22.
- Chưa thấy predicate `domain EQUALS ad.networkfilter.co` và `cmdline CONTAINS site=ad.networkfilter.co` trong EVIDENCE SUMMARY, nên độ phủ IOC theo schema `web_request` chưa đầy đủ.
- `process_creation` không thể tự chứng minh outbound HTTP beaconing; `dns` bị giới hạn thời gian; ngữ nghĩa `ip`/`port` chưa xác định.
- 0 match chỉ đúng với predicate literal, loại sự kiện hiện có và cửa sổ đã quét; không loại trừ C2 dùng host/URI khác, mã hóa, hoặc telemetry không ghi nhận.

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

- LLM (judge + advisor): 1 lần gọi, 6695 token. Các agent bên trong PEAK Assistant tự tạo client riêng nên chưa được đo.
- Thời gian chạy bước Execute (gồm lệnh gọi judge): 6.16s
- Ledger: `artifacts\runs\v2\poc-c2-beacon-networkfilter\poc-c2-beacon-networkfilter.json`
