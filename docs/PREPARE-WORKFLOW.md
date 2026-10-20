# Prepare-only: từ PoC công khai tới kế hoạch săn (và vòng xác minh)

Tài liệu này mô tả hướng mở rộng: dự án này chỉ làm chữ **P** (Prepare) của khung PEAK. Pha **E**xecute và **A**ct do đội
khác làm trên hệ thống của họ. Hai bên trao đổi bằng hai tài liệu có schema: `HuntPlan` (ta gửi đi) và `ResultBundle`
(họ gửi lại). Phần ta còn làm thêm là **xác minh** kết quả để quyết định chấp nhận hay chạy vòng tiếp theo.

## 1. Ranh giới (tránh lộ thông tin)

| Việc | Có | Không |
|---|---|---|
| Đọc nguồn công khai (NVD, GitHub: README và vài file mã/mẫu nuclei) | ✔ | |
| Chạy, cài đặt, clone PoC | | ✘ (chỉ đọc văn bản qua `raw.githubusercontent.com`) |
| Truy cập SIEM, telemetry, tên host/index/IP/user nội bộ | | ✘ (kế hoạch dùng placeholder `{{INDEX_WEB}}`...; đội Execute tự ánh xạ) |
| Gửi dữ liệu nội bộ cho LLM | | ✘ (LLM chỉ thấy văn bản công khai; kết quả thực thi chỉ được xử lý cục bộ bởi `verify`, không gọi LLM) |

`Provenance` trong mỗi kế hoạch ghi cố định `poc_executed=false`, `internal_data_used=false`, `untrusted_input=true`.

## 2. Luồng tổng thể

```text
 CVE / repo / từ khoá ─► intel.gather ─► (NVD + GitHub, có cache) ─► IntelBundle + dấu vết trích tất định
                                             │
                                             ▼
                    PEAK Assistant (tuỳ chọn): bảng ABLE + hunt plan   ◄── mô tả nguồn dữ liệu CHUNG, không phải của tổ chức
                                             │
                                             ▼
        plan.build_plan: LLM đề xuất giai đoạn + dấu vết + truy vấn SPL
        ─► mã kiểm tra từng truy vấn (allow-list, chỉ đọc, chặn tối đa, gắn cửa sổ/giới hạn) ─► sửa lại nếu sai (≤ 3 lượt)
        ─► điểm dừng, giới hạn, truy vấn độ phủ sinh từ mẫu cố định
                                             │
                                             ▼
                      HuntPlan (plan.json, plan.md, queries.spl, result.template.json)
                                             │   ──► ĐỘI EXECUTE chạy (ngoài phạm vi dự án)
                                             ▼
                      ResultBundle (results.json)
                                             │
                                             ▼
        plan.verify (tất định, không LLM): kiểm tra giao thức, độ phủ nguồn, điểm dừng theo từng giai đoạn
          ├─ ESCALATE_AFFECTED   giai đoạn 'impact' có sự kiện → chuyển IR, dừng mở rộng
          ├─ REFINE              có dấu vết ở context/indicator → sinh kế hoạch vòng sau (pivot, cửa sổ hẹp ±1h)
          ├─ COLLECT_DATA        nguồn không có dữ liệu → rỗng không chứng minh gì
          ├─ RERUN_INCOMPLETE    truy vấn lỗi / quá giờ / chưa chạy
          ├─ ACCEPT_NO_EVIDENCE  mọi thứ chạy đủ, mọi nguồn có dữ liệu, không thấy gì (KHÔNG phải "sạch")
          ├─ STOP_REVIEW         hết số vòng hoặc không còn dấu vết mới → người đọc
          └─ REJECT_RESULTS      kết quả của kế hoạch khác
```

Vòng lặp dừng khi: chuyển IR, chấp nhận, hết `max_iterations` (mặc định 3), hoặc không còn giá trị mới để pivot.

## 3. Lệnh

```bash
# 1) lập kế hoạch từ PoC công khai (CVE, repo, hoặc từ khoá). LLM là tuỳ chọn: --offline hoặc không có khoá thì chỉ có phần lõi
python main.py plan --cve CVE-2021-44228 --min-stars 500
python main.py plan --repo fullhunt/log4j-scan
python main.py plan --query "spring4shell poc" --min-stars 200 --no-peak   # --no-peak: bỏ PEAK cho nhanh

python main.py plan --cve CVE-2021-44228 --min-stars 500 --offline       # chỉ phần lõi tất định, không gọi LLM

# 2) NGƯỜI duyệt plan.md rồi làm theo RUNBOOK.md (R0, R1, ...). Gắn chỉ mục và cửa sổ thời gian; lệnh bind từ chối truy vấn không an toàn
python main.py bind --plan artifacts/plans/CVE-2021-44228/iter1/plan.json \
    --map web=web_prod --map dns=dns_prod --map proxy=proxy_prod --map endpoint=edr_prod \
    --earliest 2026-10-13T00:00:00Z --latest 2026-10-20T00:00:00Z [--accept-llm L1,L2]
#    -> queries.bound.spl (chỉ đọc, đã gắn). Đội Execute chạy tuần tự, điền result.template.json → results.json
#       (bắt buộc: plan_digest, approved_by, approved_at; accepted_llm_stages nếu có chạy gợi ý của LLM)

# 3) xác minh; nếu cần sẽ tạo thư mục iter2/ với kế hoạch vòng sau
python main.py verify --plan artifacts/plans/CVE-2021-44228/iter1/plan.json --results results.json

# JSON Schema của hai tài liệu trao đổi
python main.py schema --out schemas/
```

Không có LLM (khoá sai/hết hạn, model lỗi, hoặc `--offline`): vẫn ra kế hoạch đầy đủ phần lõi, kèm ghi chú vì sao không có gợi ý LLM. (Trước đây
bước này dừng với mã thoát 3 vì LLM cần để
viết giai đoạn và truy vấn.) `verify`, `bind` và `schema` không dùng LLM.

Biến môi trường tuỳ chọn: `GITHUB_TOKEN` (nâng hạn mức GitHub từ 60 lên 5.000 yêu cầu/giờ; chỉ gửi tới `api.github.com`),
`NVD_API_KEY`. Cache ở `artifacts/.cache/intel` (24 giờ).

## 4. Hợp đồng `HuntPlan` (tóm tắt)

| Trường | Ý nghĩa |
|---|---|
| `hypothesis` | "Giả sử PoC này được dùng để tấn công, hãy kiểm tra hệ thống có dính không" |
| `applicability` | sản phẩm, phiên bản, điều kiện để khai thác được, khi nào không áp dụng |
| `stages[]` | giai đoạn tấn công: `phase` (ATT&CK), `significance` (`context` / `indicator` / `impact`), `observables`, `queries`, `stop_conditions` |
| `observables[].basis` | `from_poc` nếu chuỗi có nguyên văn trong văn bản PoC/CVE thu thập được, ngược lại `inferred` |
| `queries[]` | SPL chỉ đọc có placeholder; `grounded` cho biết có chuỗi nào lấy nguyên văn từ PoC |
| `coverage_probes[]` | kiểm tra nguồn có dữ liệu (`tstats`, sinh từ mẫu cố định, chạy trước) |
| `limits` | cửa sổ, số dòng, số truy vấn, thời gian, số vòng, `read_only` |
| `stop_rules`, `verification` | điểm dừng toàn kế hoạch và tiêu chí chấp nhận / pivot / bổ sung dữ liệu |
| `dropped` | truy vấn bị loại và lý do; ghi chú của bộ kiểm tra |

Ý nghĩa của `significance` quyết định điểm dừng mặc định: `context` (nhiễu mong đợi, có sự kiện chỉ ghi nhận),
`indicator` (nỗ lực khớp PoC, chưa chứng minh thành công → pivot), `impact` (thành công/hậu khai thác → dừng mở rộng, chuyển IR).

Placeholder: `{{INDEX_WEB|PROXY|ENDPOINT|NETWORK|DNS|AUTH|APP}}`, `{{EARLIEST}}`, `{{LATEST}}`, `{{MAX_ROWS}}`. Hàm
`hunting.plan.bind(spl, plan, {"web": "my_web_index", ...})` gắn giá trị thật và từ chối ánh xạ không an toàn hoặc thiếu.
Tên trường theo Splunk CIM để dùng được trên nhiều triển khai.

`ResultBundle`: `plan_id`, `iteration`, `results[]` với `query_id`, `status` (`ok`/`error`/`timeout`/`skipped`), `row_count`,
`truncated`, `sample` (≤ 25 dòng). "Kết quả" của một truy vấn là số **dòng** trả về (nên truy vấn dạng `stats count by ...` cho ra
vài dòng, không phải số sự kiện).

## 5. Mô hình an toàn

Đầu vào là nội dung Internet (README, mã khai thác), có thể chứa lệnh giả mạo nhắm vào LLM. Biện pháp:

1. Văn bản PoC được đặt trong hàng rào `<<< >>>` và ghi nhãn "UNTRUSTED DATA"; system prompt yêu cầu bỏ qua mọi chỉ dẫn trong đó.
2. Đầu ra của LLM không bao giờ được thực thi. Mỗi truy vấn đi qua `plan.safety.check_spl`: phải bắt đầu bằng `search`, đúng một
   `index={{INDEX_*}}`, chỉ dùng lệnh trong danh sách cho phép (không `delete`, `outputlookup`, `sendemail`, `rest`, `join`,
   `map`...), không truy vấn con, không macro, không `$token$`, có bộ lọc ngoài index, tối đa 1.500 ký tự và 10 công đoạn;
   thời gian và `head {{MAX_ROWS}}` do mã thêm, không do LLM.
3. Mảnh payload so sánh bằng `field="..."` (khớp chính xác trong Splunk) được tự bọc `*...*` để khỏi bỏ sót im lặng.
4. Dấu vết LLM nêu mà không có trong PoC bị đánh dấu `inferred`; truy vấn không có chuỗi nào từ PoC bị đánh dấu `grounded=false`.
5. Ở vòng pivot, giá trị lấy từ log (có thể do kẻ tấn công kiểm soát) chỉ được nhúng vào truy vấn qua `spl_literal` (bộ lọc ký tự
   nghiêm ngặt) và truy vấn pivot vẫn qua `check_spl`.
6. Truy vấn lạ trong kết quả, `plan_id` sai, mẫu quá 25 dòng đều bị ghi vào `protocol_issues`; kết quả của kế hoạch khác bị từ chối.
7. **Hậu khai thác phải gắn với dịch vụ bị tấn công.** Truy vấn trên nguồn `endpoint` (tiến trình) bắt buộc *lọc* theo
   `parent_process_name`/`parent_process` (ví dụ `java` với ứng dụng Java, `w3wp.exe` với IIS); chỉ nhắc tới trường này trong
   `stats ... by` thì không tính. Lý do: `whoami` hay một shell do quản trị viên chạy trông y hệt khi chạy qua webshell, chỉ tiến trình cha
   phân biệt được. Truy vấn thiếu bị gửi lại để sửa; còn thiếu sau các lượt sửa thì bị loại và ghi vào `dropped`. Truy vấn về file/registry được miễn.
   Một giai đoạn mất hết truy vấn được in cảnh báo trong `plan.md`, và `verify` coi là `INCOMPLETE` (không bao giờ `CLEAR`).
8. **Chữ lẫn ngôn ngữ khác.** Ngoài việc loại ký tự CJK/Cyrillic/Ả Rập, `plan/language.py` phát hiện từ không phải tiếng Việt
   cũng không phải tiếng Anh (`przeciwko`, `tentativa`, `explotación`, `ungewö...`): chữ cái không có trong tiếng Việt lẫn tiếng Anh
   thì chắc chắn; từ nào không phải âm tiết tiếng Việt hợp lệ, không có trong từ vựng tiếng Anh dùng trong kế hoạch và không xuất hiện trong
   văn bản PoC/CVE thì bị gắn cờ. Việc này chỉ yêu cầu viết lại một lần (không loại truy vấn) và liệt kê từ còn sót trong `dropped`.
   Đây là heuristic cho trường văn bản để người đọc, không phải biện pháp an ninh.
9. Mọi yêu cầu HTTP ra ngoài chỉ tới 3 host cho phép; **chuyển hướng cũng bị kiểm tra lại từng bước** (https, đúng host, tối đa 3 lần),
   và khoá API chỉ đi cùng yêu cầu tới host của nó.

## 5b. Ba bảo đảm (phiên bản 0.4)

**A. Kết quả không phụ thuộc model.** Kế hoạch có hai phần với mức tin cậy khác nhau (trường `origin` của từng giai đoạn/truy vấn):

| Phần | Ai tạo | Phụ thuộc model? | Dùng để quyết định? |
|---|---|---|---|
| `core` (S1 ngữ cảnh, S2 dấu hiệu nỗ lực, S3 hậu khai thác; truy vấn, điểm dừng, giới hạn, độ phủ) | **Mã** (`plan/core.py`), từ dấu vết trích trong PoC/CVE | **Không**: cùng tình báo thì cùng `core_digest` | **Có**: chỉ phần này quyết định `verify` |
| `llm` (tối đa 2 giai đoạn × 2 truy vấn, mã `L1`, `L2`) | LLM qua PEAK, qua cùng bộ kiểm tra | Có | **Không**: người chấp nhận từng cái; kết quả chỉ để tham khảo, không leo thang/pivot |

Model yếu, hỏng, hết hạn khoá hay không có model: phần lõi y hệt (đã kiểm chứng bằng `core_digest`), chỉ ít gợi ý hơn. Model mạnh hơn
cho nhiều gợi ý hơn, nhưng không đổi, không bớt được một truy vấn lõi. Bộ kiểm tra tiến trình cha, ngoại ngữ, an toàn SPL áp như nhau cho cả hai phần.

**B. Người quyết định từng bước.** Mỗi kế hoạch sinh `RUNBOOK.md` bằng mã (không bằng LLM): R0 duyệt kế hoạch → R1 gắn chỉ mục/thời gian →
độ phủ → từng truy vấn (một bước mỗi truy vấn, kèm "ghi lại" và "dừng nếu") → **cổng người** sau mỗi giai đoạn → nộp kết quả → quyết định cuối.
Kết quả trả về phải nhắc `plan_digest`, tên người duyệt (`approved_by`) và thời điểm (`approved_at`), nếu không `verify` trả `REJECT_RESULTS`;
gợi ý của LLM chỉ được tính khi liệt kê trong `accepted_llm_stages`. Vòng pivot (`REFINE`) là một kế hoạch mới với `plan_digest` mới: phải duyệt lại.

**C. SPL và thời gian được kiểm tra hai lần**: lúc lập kế hoạch (`check_spl`) và lúc gắn (`bind` → `lint_bound`), nên sửa tay `plan.json` cũng không lọt.

| Chặn | Cách |
|---|---|
| `index=*`, chỉ mục thiếu/sai/nội bộ (`_internal`, `_audit`), nhiều chỉ mục | `index_name_problem`: một chỉ mục thật (hoặc tiền tố `web_*` ≥ 3 ký tự) |
| Tìm kiếm không có bộ lọc chọn lọc (`field=*`, chuỗi < 3 ký tự) | `check_spl`: phải có literal ≥ 3 ký tự ngoài ký tự đại diện |
| Thiếu mốc thời gian, `earliest`/`latest` do lệnh sau chèn vào | `bind` luôn chèn mốc **tuyệt đối** (epoch); `lint_bound` bắt buộc có cả hai |
| Cửa sổ đảo ngược, rộng hơn 90 ngày, kết thúc trong tương lai | `resolve_window`; `Limits.lookback`/`window` cũng chặn lúc lập kế hoạch |
| Kết quả không giới hạn (`head` thiếu, `limit=0`, `sort 0`) | `head N` bắt buộc, `1 ≤ N ≤ max_rows`; cấm `limit=0`, `sort 0` |
| Lệnh giữ cả tập kết quả trong bộ nhớ (`eventstats`, `streamstats`, `mvexpand`, `makemv`) | bỏ khỏi danh sách cho phép |
| Nhóm/liệt kê/khử trùng trên `_raw` (mỗi sự kiện một giá trị → tràn bộ nhớ) | `check_spl`, `lint_bound` |
| Placeholder còn sót, ánh xạ thiếu nguồn | `bind` từ chối cả lô, in mọi lỗi cùng lúc, không ghi file nào |

## 6. Giới hạn đã biết

- **Phần lõi tất định thận trọng và hẹp**: chỉ tìm đúng chuỗi có trong PoC/CVE, không suy luận biến thể; không dựng truy vấn tiến trình khi chưa suy ra được
  tiến trình cha từ tên sản phẩm (ghi vào "Việc con người phải tự làm"). Độc lập model nghĩa là *cùng kế hoạch lõi*, không phải *cùng chất lượng gợi ý*:
  gợi ý LLM vẫn tốt/xấu tuỳ model, nhưng không ảnh hưởng quyết định.
- **Chất lượng gợi ý của LLM phụ thuộc vào model.** Mô hình miễn phí dùng để thử (Nemotron) đôi khi chọn nguồn dữ liệu chưa tối ưu hoặc lẫn
  từ nước ngoài trong chữ tiếng Việt (mã loại ký tự CJK/Cyrillic/Ả Rập và yêu cầu viết lại từ Latin ngoại ngữ, xem mục 5, ý 8). Bộ kiểm tra chỉ bảo đảm *an toàn và hình thức*,
  không bảo đảm truy vấn *bắt đúng* tấn công. Người săn phải đọc kế hoạch trước khi giao cho đội Execute.
- **Chưa chạy SPL trên Splunk thật** (cũng như các lệnh `tstats` độ phủ). Tên trường theo CIM có thể khác ở mỗi nơi.
- `ACCEPT_NO_EVIDENCE` chỉ nói "không thấy trong phạm vi đã quét", không bao giờ là "sạch": chỉ các biến thể nêu trong kế hoạch được tìm.
- Vòng pivot dùng mẫu truy vấn cố định (nguồn tấn công, host bị nhắm tới, tiến trình shell, tên miền out-of-band, tài khoản). Kết quả
  của vòng đó cần người đọc nếu có sự kiện: mã không có đường cơ sở để phân biệt shell hợp lệ.
- Hạn mức GitHub không token là 60 yêu cầu/giờ (một lần lập kế hoạch tốn khoảng 23 yêu cầu; có cache).
- Chọn PoC theo số sao là tín hiệu yếu về độ tin cậy; PoC có thể lỗi thời, đã lưu trữ hoặc sai. Kế hoạch ghi cảnh báo `archived`/`below_threshold`.
- Pipeline cũ (`python main.py --poc-dir pocs ...`, chạy Execute trên dữ liệu BOTS v1 công khai) vẫn còn, dùng làm bộ thử
  cục bộ chứ không còn là hướng chính.
