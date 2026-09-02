# FOUNDATIONAL REVIEW — Cell, EventFamily và Query Space
## Principal Security Architect review, dựa trên tài liệu chính thức của backend

---

# 1. EXECUTIVE VERDICT

## **CONDITIONAL GO FOR LIMITED POC ONLY**

Không phải NO-GO, vì phần lớn kiến trúc (ledger, epistemic layer, constraint, stopping, disposition, LLM boundary) không phụ thuộc vào lỗi này. Không phải GO, vì **`event_family` là một chiều bắt buộc của `Cell` là sai ở tầng nền tảng**, và nó sẽ hỏng ngay khi rời CDB.

Cụ thể theo tiêu chí mục 11 của bạn:

| Tiêu chí GO | Mô hình hiện tại |
|---|---|
| không cần khai báo trước mọi event type/code/field | **KHÔNG ĐẠT** |
| EDR không có event code vẫn hoạt động | **KHÔNG ĐẠT** |
| IDS schema biến đổi vẫn hoạt động | **KHÔNG ĐẠT** |
| Splunk index nhiều record type vẫn hoạt động | **KHÔNG ĐẠT** |
| event chưa biết không bị drop | KHÔNG ĐẠT (rơi vào `other`) |
| event chưa map không bị gán nhãn sai | KHÔNG ĐẠT |
| query không khả dụng được báo rõ | đạt |
| coverage không tính unknown thành explored | đạt |
| backend mới thêm qua adapter | một phần |
| LLM không có đường tới raw query | **đạt** |
| test quan trọng có execution evidence | chỉ trên CDB |

POC hợp lệ vì CDB là backend duy nhất có event code cho mọi record — đúng là trường hợp đặc biệt mà mô hình A tình cờ đúng. Đó là lý do lỗi này không bị phát hiện qua 7 thực nghiệm.

---

# 2. LỖI NỀN TẢNG

`event_family` đang gánh **ba vai trò khác nhau**, khác nhau về chủ sở hữu, về lực lượng, và về tính đóng/mở:

| Vai trò | Ai định nghĩa | Đóng hay mở | Có luôn tồn tại? |
|---|---|---|---|
| **R1. Addressability** — cái bạn đặt được vào câu query | backend | **đóng theo deployment**, khám phá được | **có** |
| **R2. Semantics** — sự kiện này *là loại gì* | thế giới | **mở, vô hạn** | **không** |
| **R3. Evidence requirement** — cuộc điều tra *cần gì* | MITRE / phía câu hỏi | đóng, nhỏ | n/a |

Gộp ba thứ này vào một closed enum tạo ra bốn hệ quả hỏng:

**(a) Không liệt kê trước được.** R2 mở. Suricata 8.0 tài liệu hoá **25+ `event_type`**, và tập này *đang tăng* — `pop3`, `arp`, `pgsql`, `bittorrent-dht` là các loại mới. Bản 8.0 còn đổi DNS logging sang version 3 và bỏ version 2 ở Suricata 9. Schema thay đổi theo *phiên bản phần mềm*, không chỉ theo vendor.

**(b) Family không quyết định field.** Đây là điểm chí mạng. Theo tài liệu Suricata, HTTP có "extended logging" bật/tắt được, cộng **hơn 50 field HTTP tuỳ chọn** khai báo trong `suricata.yaml`; DNS cho chọn RR type nào được log; SMB cho chọn 9 loại transaction; JA3/JA4 phải bật riêng. Nghĩa là **field presence là hàm của cấu hình deployment, không phải của event type**. Giả định "family ⇒ field set" trong C4/C10 của tài liệu hiện tại là sai.

**(c) Event type không phải một tầng.** RDP trong EVE có `event_type: "rdp"` ở ngoài và **một `event_type` lồng bên trong** (`initial_request`, `connect_request`, `tls_handshake`). Một enum phẳng không mô hình hoá được.

**(d) Splunk không addressable theo family.** Một index chứa nhiều sourcetype; một sourcetype có thể chứa nhiều định dạng event; sourcetype **có thể đổi tên lúc search-time**; field extraction chủ yếu xảy ra **lúc search-time** theo props/transforms. Cái Splunk cho bạn địa chỉ hoá là `index` + `sourcetype` + `source`. Không có "event_family" nào để đặt vào query.

**(e) EDR không có event code.** API EDR là endpoint theo *chức năng* (process search, process tree, network search, file activity), trả **relationship** chứ không chỉ event record, schema khác nhau giữa endpoint, phân trang bằng cursor. Không có trục nào tương ứng `event_family`.

**Kết luận:** lỗi không nằm ở việc chọn sai tập family. Lỗi nằm ở việc **coi family là một chiều của không gian địa chỉ**. Không gian địa chỉ thuộc về backend; ngữ nghĩa thuộc về thế giới; hai thứ này không được là cùng một trục.

---

# 3. `Cell` NÊN ĐƯỢC ĐỊNH NGHĨA LẠI THẾ NÀO

`Cell` chỉ có một công dụng duy nhất: **đơn vị kế toán coverage — thứ nhỏ nhất mà ta có thể nói "đã hỏi" hay "chưa hỏi"**. Nó không phải đơn vị ngữ nghĩa.

Muốn đếm được, mỗi chiều phải liệt kê được **trước khi truy vấn**. R2 không liệt kê được ⇒ **loại family khỏi Cell**.

```python
ProviderScope = {provider_id*, native_partition*}
    # native_partition là địa chỉ NGUYÊN BẢN của backend, không dịch:
    #   Splunk : {"index": "wineventlog", "sourcetype": "XmlWinEventLog"}
    #   EDR    : {"endpoint": "/processes/search"}
    #   IDS    : {"stream": "eve.json", "host": "sensor-01"}
    #   CDB    : {"channel": "Security"}

Cell = {provider_scope*: ProviderScope,
        entity*: EntityRef | ANY,
        time_bucket*}
```

`native_partition` là **cái backend tự khai báo và ta khám phá được** — `| metadata type=sourcetypes index=X` cho Splunk, danh sách endpoint cho EDR, danh sách stream cho IDS. Nó đóng theo deployment, đúng điều kiện đếm được.

**Family biến mất khỏi Cell.** Coverage giờ là câu nói trung thực: *"tôi đã hỏi partition này, cho entity này, trong cửa sổ này"* — thứ ta thực sự biết. Câu cũ *"tôi đã hỏi family process_creation"* là câu ta **không** biết, vì không thể chứng minh mọi process creation đều mang family đó.

---

# 4. `EventFamily` NÊN ĐƯỢC ĐỊNH NGHĨA LẠI THẾ NÀO

Tách làm hai vật thể khác nhau, không cái nào là chiều của Cell:

### 4.1 `SemanticType` — nhãn hậu nghiệm, nullable, mở

```python
Observation.semantic_type: SemanticType | None
SemanticType = {vocabulary*, value*, confidence_basis*, mapped_by*}
    # vocabulary: "ocsf" | "attack_data_component" | "local" | "native"
    # mapped_by : "deterministic_rule" | "adapter" | "unmapped"
```

Quy tắc bất di bất dịch: **`semantic_type = None` là hợp lệ và observation vẫn đầy đủ giá trị.** Nó vẫn vào ledger, vẫn có entity, vẫn attributable, vẫn vào `unattributed` nếu không explanation nào giải thích được, vẫn kích hoạt abduction. Không có thùng rác `OTHER`.

`native_type` (ví dụ `event_type: "pgsql"`, `EventID: 4688`) được **giữ nguyên văn** và tách khỏi `semantic_type`. Suricata có tiền lệ đúng cho việc này: với anomaly loại `unknown`, nó thêm field `code` chứa **mã sự kiện không nhận dạng được** thay vì vứt đi.

### 4.2 `EvidenceRequirement` — từ vựng phía câu hỏi, đóng, nhỏ

Đây là cái Expectation nên nói, thay vì `event_family`:

```python
EvidenceRequirement ∈ {process_ancestry, process_execution, logon_activity,
                       network_connection, dns_resolution, file_modification,
                       persistence_config, module_load, ...}
```

Đây gần trùng **MITRE ATT&CK Data Components**, vốn tồn tại đúng để trả lời "muốn thấy hành vi X thì cần loại dữ liệu nào". Dùng lại từ vựng đó thay vì tự chế.

**Family không được giới hạn query của agent.** Một `EvidenceRequirement` ánh xạ tới **nhiều** provider operation qua bảng capability; và một provider operation có thể phục vụ **nhiều** requirement. Quan hệ nhiều–nhiều, không phải một chiều enum.

---

# 5. QUERY SPACE THỰC SỰ CỦA AGENT

```
question
  → EvidenceRequirement           (đóng, nhỏ, phía câu hỏi)
  → CapabilityBinding             (bảng cấu hình: requirement × provider → operation)
  → ProviderOperation             (nguyên bản của backend, có tham số hợp lệ)
  → native query                  (template, validated, có limit + cursor)
  → rows + completeness
  → Observation (native_type giữ nguyên)
  → semantic_type (tuỳ chọn, có thể None)
```

`ProviderOperation` là **cái backend thực sự làm được**, khai báo trong adapter:

| Backend | Operation | Tham số |
|---|---|---|
| Splunk | `spl_search` | index, sourcetype?, entity predicate, earliest, latest, limit |
| EDR | `process_search` / `process_tree` / `network_search` / `file_activity` | entity, window, cursor |
| IDS | `eve_scan` | stream, event_type?, 5-tuple/flow_id predicate, window, limit |

Không operation nào yêu cầu `event_family`. `event_type` của Suricata là **predicate tuỳ chọn**, không phải chiều bắt buộc.

---

# 6. SO SÁNH MODEL A / B / C

| Tiêu chí | **A — Family-centric** | **B — Provider/operation-centric** | **C — Capability-centric** |
|---|---|---|---|
| Splunk | **Không.** Không có trục family để địa chỉ hoá; index↔sourcetype nhiều–nhiều; sourcetype đổi tên search-time | **Có.** index+sourcetype là địa chỉ nguyên bản | Có, nhưng phải qua binding |
| EDR | **Không.** Không có event code | **Có.** endpoint = partition | **Rất hợp.** endpoint vốn đã là capability |
| IDS | **Không.** `event_type` mở và đổi theo version | **Có.** stream = partition, `event_type` là predicate | Có |
| Event chưa biết | **Rơi vào `other`** hoặc bị drop | **Giữ nguyên vẹn** trong partition đã biết | Giữ, nhưng chỉ nếu có capability phủ |
| Metadata phải khai trước | **Rất cao** — mọi family, mọi field | **Thấp** — chỉ danh sách partition, khám phá được | **Trung bình** — bảng binding thủ công |
| Query event không có event code | Không | **Có** | Có |
| Field tuỳ chọn | Giả định sai "family ⇒ field" | Field là quan sát hậu nghiệm | Requirement nêu field cần, kiểm tra runtime |
| Tính coverage | Mẫu số **không đếm được** | **Đếm được** từ registry | Đếm được nhưng theo capability, khó đối chiếu dữ liệu thô |
| Pagination/truncation | không mô hình hoá | **cursor + complete tự nhiên** | tương tự |
| Mất evidence | **Có** | Không | **Có** — evidence ngoài mọi capability sẽ vô hình |
| Thêm backend mới | Phải map vào family có sẵn | **Thêm adapter là xong** | Phải viết binding cho từng requirement |
| Chi phí vận hành | Cao và tăng theo thời gian | Thấp | Trung bình |
| Failure mode chính | gán nhãn sai + drop im lặng | partition quá thô ⇒ query đắt | **capability gap ⇒ mù có hệ thống** |

### Vì sao không được mặc định B hoặc C đúng

**C một mình là nguy hiểm.** Nếu Cell = capability, thì thứ không có capability **không tồn tại trong mẫu số coverage** — hệ thống sẽ báo coverage cao trong khi mù một vùng dữ liệu. Đó chính xác là lỗi "coverage over-reporting" mà tiêu chí 11 cấm.

**B một mình là không đủ.** Provider scope cho bạn kế toán trung thực nhưng **không cho bạn biết phải hỏi gì**. Expectation cần một từ vựng phía câu hỏi.

---

# 7. MÔ HÌNH PHÙ HỢP NHẤT

## **B cho trục kế toán, C cho trục truy vấn. Lai, không thuần.**

```
Coverage axis (B):   Cell = (ProviderScope, entity|ANY, time_bucket)
                     → đếm được, trung thực, không phụ thuộc ngữ nghĩa

Query axis (C):      EvidenceRequirement → CapabilityBinding → ProviderOperation
                     → biết phải hỏi gì, ánh xạ nhiều–nhiều

Semantic axis:       Observation.semantic_type: nullable, hậu nghiệm
                     → không bao giờ chặn ingest, không bao giờ chặn coverage
```

Lý do chọn tổ hợp này chứ không phải một model thuần:

1. **Mẫu số coverage phải độc lập với hiểu biết ngữ nghĩa.** Nếu không, coverage sẽ tăng khi ta hiểu thêm và không phản ánh dữ liệu thực. Chỉ B cho tính chất đó.
2. **Capability gap phải nhìn thấy được.** Vì Cell theo B, một partition không có capability nào vẫn nằm trong mẫu số và hiện ra là `UNQUERYABLE` — không biến mất.
3. **Semantic mapping là tuỳ chọn nên không bao giờ mất event.** Sự kiện lạ vẫn thành Observation, vẫn vào `unattributed`, vẫn kích abduction. Đó chính là cơ chế mở-thế-giới mà kiến trúc vốn muốn.

---

# 8. BẰNG CHỨNG CHO TỪNG QUYẾT ĐỊNH

| Quyết định | Bằng chứng | Phân loại |
|---|---|---|
| `event_type` là tập mở, đổi theo version | Suricata 8.0 EVE doc: 25+ event type; DNS logging v3 thay v2, v2 bị bỏ ở Suricata 9 | **OFFICIAL SYSTEM DOCUMENTATION** |
| Field presence phụ thuộc cấu hình, không phụ thuộc type | Suricata EVE doc: HTTP extended logging + >50 custom field; DNS chọn RR type; SMB chọn 9 transaction type; JA3/JA4 phải bật | **OFFICIAL SYSTEM DOCUMENTATION** |
| Event type có thể lồng nhau | Suricata EVE doc: RDP có `event_type` bên trong (`initial_request`, `connect_request`, `tls_handshake`) | **OFFICIAL SYSTEM DOCUMENTATION** |
| Backend có sẵn cơ chế "unknown type" | Suricata EVE doc: anomaly `type: "unknown"` kèm field `code` chứa mã không nhận dạng được | **OFFICIAL SYSTEM DOCUMENTATION** |
| Truncation là khái niệm gốc, không phải ta chế ra | Suricata EVE doc: MQTT truncated ⇒ `"truncated": true` + `"skipped_length"` | **OFFICIAL SYSTEM DOCUMENTATION** |
| Khoá tương quan là entity/flow, không phải type | Suricata EVE doc: `flow_id` tương quan alert/http/fileinfo/anomaly/flow với nhau | **OFFICIAL SYSTEM DOCUMENTATION** |
| Một index chứa nhiều sourcetype | Splunk Splexicon + community: nhiều sourcetype/index là chuẩn mực | **OFFICIAL + COMMUNITY DOCUMENTATION** |
| Field extraction ở search-time, cấu hình theo props | Splunk community/add-on docs: search-time extraction là mặc định; index-time chỉ khi có lý do đặc biệt | **OFFICIAL VENDOR ADD-ON DOCUMENTATION** |
| Sourcetype có thể đổi tên lúc search-time | Splunk props.conf `rename` | **OFFICIAL SYSTEM DOCUMENTATION** |
| Một data source có nhiều định dạng event | Splunk community: một log chứa 15 định dạng, 1–4 biến thể mỗi loại | **COMMUNITY / ANALOGICAL** |
| MITRE Data Components là từ vựng evidence-requirement sẵn có | attack.mitre.org/datacomponents | **CHƯA XÁC MINH — phải fetch trước khi trích dẫn** |
| OCSF / OpenTelemetry events giải quyết normalization | ocsf.io, opentelemetry.io | **CHƯA XÁC MINH** |
| Matryoshka / SynRAG / Sieve / GCLC | 4 arXiv/IEEE | **CHƯA XÁC MINH — chưa đọc** |
| Wildcard cell + cell-prevalence clustering 14.26× | E7 trên CDB, n=1 sample, 2 bucket | **DIRECT EMPIRICAL EVIDENCE, phạm vi rất hẹp** |

**Tôi đã đọc trực tiếp tài liệu Suricata EVE 8.0 và một phần tài liệu Splunk. Tôi CHƯA đọc OCSF, OpenTelemetry, MITRE Data Components, và cả bốn paper.** Không được trích dẫn chúng như bằng chứng cho tới khi kiểm tra. Theo đúng ràng buộc của bạn: không dùng paper trên dataset nhỏ để khẳng định production completeness — và E7 là đúng loại bằng chứng hẹp đó.

---

# 9. PHẦN CHỈ LÀ ORIGINAL ENGINEERING DESIGN

Đánh dấu rõ, không có literature chống lưng:

- `ProviderScope.native_partition` như chiều của Cell — **ORIGINAL**
- Tách ba trục coverage/query/semantic — **ORIGINAL** (dù mỗi trục riêng lẻ có tiền lệ)
- Bốn trạng thái unknown (mục 10) — **ORIGINAL**
- `CapabilityBinding` nhiều–nhiều — **ENGINEERING** (giống service-registry pattern)
- Three-stage control query — **ORIGINAL, UNSUPPORTED** (từ vòng trước)
- Wildcard cell + subsumption + bucket split — **ORIGINAL**, có bằng chứng E7 hẹp
- `semantic_type = None` không chặn gì — **ORIGINAL**, có tiền lệ gián tiếp từ cơ chế anomaly `unknown` + `code` của Suricata

---

# 10. XỬ LÝ EVENT CHƯA BIẾT

`UNKNOWN-TO-AGENT` phải tách làm **bốn** trạng thái, đúng như bạn nêu:

| Trạng thái | Nghĩa | Đếm được? |
|---|---|---|
| `UNKNOWN_SOURCE` | provider không có trong catalog | **Không** — bất khả tri |
| `UNQUERYABLE` | provider biết, chưa có adapter/operation | **Có** — nằm trong mẫu số, báo cáo rõ |
| `UNMAPPED` | query được, event nhận được, chưa có semantic mapping | **Có** — observation đầy đủ |
| `UNEXPLAINED` | đã map (hoặc không cần map), nhưng không explanation nào giải thích | **Có** — chính là `unattributed` |

Chỉ trạng thái đầu là thật sự không đếm được. Ba trạng thái sau đều hiện ra trong coverage bound.

## Lifecycle từng loại event

| Loại | Nhận | Lưu | Ledger | Observation | Cell | Query tiếp | Coverage | Tạo hypothesis | Ảnh hưởng disposition |
|---|---|---|---|---|---|---|---|---|---|
| **Event đã biết** | có | có | có | có | có | có | explored | có | bình thường |
| **Event lạ, source đã biết** | **có** | **có** | **có** | **có, `semantic_type=None`** | có (partition đã biết) | có | **explored** | **có — vào `unattributed`, kích abduction** | có thể dẫn tới `UNKNOWN` |
| **Có native type, chưa semantic mapping** | có | có | có | có, `mapped_by="unmapped"` | có | có | explored | có | như trên |
| **Không có event code** | có | có | có | có, `native_type=None` | có | có | explored | có | như trên |
| **Thiếu field** | có | có | có | có | có | có | explored, nhưng `field_presence[f]=False` | có | **chặn `VALID_NEGATIVE` cho field đó** |
| **Source query được, chưa có adapter** | không | n/a | n/a | không | **có, đánh dấu `UNQUERYABLE`** | **không** | **KHÔNG tính là explored** | không | **đóng góp `INSUFFICIENT_EVIDENCE`** |
| **Source hoàn toàn chưa biết** | không | n/a | n/a | không | **không** | không | **KHÔNG xuất hiện ở mẫu số** | không | **không thể phát hiện — hạn chế nền tảng** |

**Không có nhánh `unknown → OTHER → coi như xử lý xong`.** Nhánh duy nhất mất event là `UNKNOWN_SOURCE`, và đó là hạn chế phải tuyên bố, không phải che.

---

# 11. XỬ LÝ SPLUNK

```yaml
provider: splunk_prod
  operations:
    - id: spl_search
      params: [index, sourcetype?, entity_predicate, earliest, latest, limit]
      pagination: offset/count
      truncation: kết quả trả về = limit ⇒ complete=False
  partitions_discovered_by: "| metadata type=sourcetypes index=*"
  # KHÔNG khai báo event_family. KHÔNG khai báo field.
```

- **Partition = (index, sourcetype).** Khám phá được bằng chính Splunk, không phải khai tay.
- **Field là quan sát hậu nghiệm.** Vì extraction xảy ra ở search-time và phụ thuộc props/transforms, adapter chỉ ghi nhận field nào *thực tế xuất hiện* trong kết quả, ghi vào `state.field_presence`. Không giả định.
- **Sourcetype rename:** ghi cả `sourcetype` lẫn `_sourcetype` vào provenance, vì hai giá trị có thể khác nhau.
- Một index nhiều sourcetype không còn là vấn đề: mỗi (index, sourcetype) là một partition riêng.

---

# 12. XỬ LÝ EDR

```yaml
provider: edr_vendor
  operations:
    - {id: process_search,  params: [host?, name?, hash?, window, cursor]}
    - {id: process_tree,    params: [process_guid, direction, depth]}
    - {id: network_search,  params: [host?, ip?, port?, window, cursor]}
    - {id: file_activity,   params: [host?, path?, hash?, window, cursor]}
  partitions: một partition cho mỗi operation
  pagination: cursor
  rate_limit: {rps, burst}
```

- **Endpoint chính là partition** — không cần bịa event_family.
- **Relationship response** (như process tree) là hạng nhất: kết quả là quan hệ, được mint thành Observation có `native_type="relationship"` và các entity ở hai đầu. Không ép thành event record.
- **Cursor pagination:** `complete=False` khi còn cursor và đã chạm limit; áp dụng đúng quy tắc truncation đã chốt (được `CONFIRMED`, không bao giờ `REFUTED`, không cấp `VALID_NEGATIVE`).
- Schema khác nhau giữa endpoint không sao, vì field là hậu nghiệm.

---

# 13. XỬ LÝ IDS

```yaml
provider: suricata_sensor01
  operations:
    - id: eve_scan
      params: [stream, event_type?, flow_id?, ip_predicate?, window, limit]
  partitions: một partition cho mỗi (stream, sensor)
```

- **Envelope chung là thứ deterministic khai thác được.** Suricata đảm bảo mọi bản ghi có `timestamp`, `flow_id`, `event_type`, và tuple mạng. Đó là hợp đồng ổn định để extract entity và time — **không cần biết payload là gì**.
- **`event_type` là predicate tuỳ chọn**, không phải chiều bắt buộc. Loại chưa biết vẫn khớp `eve_scan` không có predicate.
- **`flow_id` là khoá tương quan.** Nên xem nó như một `EntityRef` loại `flow` — vì tài liệu chỉ rõ nó liên kết alert, http, fileinfo, anomaly và flow của cùng một phiên.
- **`event_type` lồng** (RDP): giữ ở `native_type` dạng đường dẫn, ví dụ `rdp/connect_request`. Không làm phẳng.
- Payload lồng và field tuỳ chọn: extract theo envelope, phần còn lại giữ nguyên trong `raw`.

---

# 14. CONTRACT TỐI THIỂU

```python
ProviderScope = {provider_id*, native_partition*: dict}
Cell          = {provider_scope*, entity*: EntityRef | ANY, time_bucket*}

ProviderOperation = {id*, provider_id*, params_schema*, pagination*,
                     limit_semantics*, rate_limit?}
CapabilityBinding = {evidence_requirement*, provider_id*, operation_id*,
                     param_mapping*, confidence*: EXACT | PARTIAL}
                     # nhiều-nhiều

Observation = {id*, provider_scope*, cell_id*, timestamp*,
               native_type*: str | None,          # nguyên văn, không dịch
               semantic_type*: SemanticType | None,# NULLABLE — hợp lệ khi None
               fields*{}, taint*{}, entities*[EntityRef],
               raw_ref*, provenance*, attributed_by*[]}

Expectation.evidence_requirement*   # THAY THẾ event_family
QueryResult   = {..., complete*: bool, cursor?, rows?, observed_fields*[]}

CoverageBound = {..., cells_by_state: {EXPLORED, PARTIAL, UNEXPLORED,
                                       UNQUERYABLE, UNREACHABLE},
                 unmapped_observations: int,
                 providers_without_adapter: [provider_id]}
```

**Bốn bất biến:**
1. `semantic_type = None` **không bao giờ** chặn ingest, ledger, attribution hay abduction.
2. `native_type` luôn giữ nguyên văn, không bao giờ bị chuẩn hoá mất mát.
3. Coverage đếm theo `ProviderScope`, **không bao giờ theo semantic**.
4. `UNQUERYABLE` nằm **trong** mẫu số; `UNKNOWN_SOURCE` nằm ngoài và phải được tuyên bố.

---

# 15. TEST PLAN — so sánh A/B/C

Chạy cùng 12 case trên cả ba model, cùng dữ liệu, cùng budget.

| # | Case | Dữ liệu | Metric quyết định |
|---|---|---|---|
| 1 | Splunk index nhiều sourcetype | mock Splunk, 1 index × 5 sourcetype | event retention rate; số partition đếm đúng |
| 2 | Event không có EventCode | Splunk syslog / EDR record | **event drop rate** |
| 3 | EDR endpoint không có family | mock 4 endpoint | query execution rate |
| 4 | IDS event_type chưa biết | EVE với `event_type` bịa (`"foobar"`) | **event drop rate; misclassification rate** |
| 5 | Record thiếu field | EVE HTTP không extended | false `VALID_NEGATIVE` rate |
| 6 | Một câu hỏi cần hai provider | requirement `network_connection` → EDR + IDS | evidence recall |
| 7 | Một provider trả nhiều loại câu hỏi | EVE stream phục vụ dns + network + tls | required-field coverage |
| 8 | Pagination | cursor 3 trang | evidence recall; query cost |
| 9 | Truncation | limit < kết quả | **coverage over-reporting; false REFUTED rate** |
| 10 | Source có nhưng chưa có adapter | provider khai báo, adapter thiếu | **coverage over-reporting** (phải ra `UNQUERYABLE`) |
| 11 | Event thấy nhưng không map được | native_type lạ | **unknown discovery rate; misclassification rate** |
| 12 | Source hoàn toàn ngoài catalog | provider ẩn | phải **thất bại và tuyên bố**, không được báo coverage cao |

**Ngưỡng quyết định.** Model nào có `event drop rate > 0` ở case 2/4/11, hoặc `coverage over-reporting > 0` ở case 9/10, bị loại. Dự đoán của tôi: **A trượt case 2, 3, 4, 11; C trượt case 10 và 12; B+C lai qua tất cả trừ 12 (bất khả)**. Dự đoán này phải được kiểm chứng, không được coi là kết quả.

---

# 16. PHẢI CHỐT TRƯỚC KHI CODE

Bốn quyết định, đều là **data-contract**, sửa sau rất đắt:

1. **Bỏ `event_family` khỏi `Cell`; thay bằng `ProviderScope`.** Đây là thay đổi schema của M1 — nếu viết M1 xong mới sửa thì phải viết lại ledger, coverage, sampling và toàn bộ test.
2. **`Observation.semantic_type` nullable, `native_type` giữ nguyên văn.**
3. **`Expectation.evidence_requirement` thay `event_family`.**
4. **`CoverageBound` thêm `UNQUERYABLE` và `unmapped_observations`.**

Ba điều này không phải mở lại tranh luận kiến trúc: **năm module, LLM boundary, epistemic layer, stopping, disposition đều không đổi.** Chỉ trục địa chỉ đổi.

---

# 17. CÓ THỂ DEFER

- Bảng `CapabilityBinding` đầy đủ — MVP chỉ cần binding cho CDB.
- Semantic mapping sang OCSF hoặc ATT&CK Data Components — V2, sau khi xác minh hai nguồn đó.
- Adapter Splunk/EDR/IDS thật — V1/V2.
- Rate limit, cursor resume, retry policy chi tiết.
- Tự động khám phá partition (MVP khai tay danh sách partition của CDB).
- Xác minh 4 paper và OCSF/OTel/MITRE.

---

# 18. KẾT LUẬN — đã được bắt đầu code chưa?

**Được, nhưng phải sửa contract trước, không phải sửa sau.**

Cụ thể:

```
Sửa ngay, trước dòng code đầu tiên của M1 (khoảng 1 ngày):
    Cell: bỏ event_family, thêm ProviderScope
    Observation: native_type + semantic_type nullable
    Expectation: evidence_requirement
    CoverageBound: UNQUERYABLE + unmapped_observations

Sau đó MVP tiến hành bình thường trên CDB:
    CDB thành provider có 11 partition (theo Channel)
    binding: mỗi EvidenceRequirement → cdb_query với predicate
    zero LLM call, cả alert có entity lẫn không có entity

KHÔNG được tuyên bố production-ready cho Splunk/EDR/IDS
cho tới khi test 1-12 có execution evidence trên adapter thật.
```

**Không cần loại bỏ toàn bộ kiến trúc.** Bốn trong năm module không bị ảnh hưởng. Nhưng phần bị ảnh hưởng — trục địa chỉ của Cell — là phần mà **mọi thứ khác đứng lên trên**, nên nó phải đúng trước khi M1 tồn tại.

Một điều tôi phải nói thẳng về quá trình: mô hình A sống sót qua bảy thực nghiệm vì **cả bảy đều chạy trên CDB**, backend duy nhất mà mọi record đều có event code. Đó là lời cảnh báo về giá trị của bằng chứng thực nghiệm trên một môi trường duy nhất — nó xác nhận rằng hệ thống chạy, không xác nhận rằng mô hình đúng. Test case 1–12 ở trên tồn tại chính để tránh lặp lại lỗi đó.
---

# 19. ERRATA — authoritative v3 corrections

The review above identified the right fault line, but the following corrections
are authoritative and are now implemented in `01` and `02`:

1. An unknown event in a known scope is **not** automatically `explored`.
   `EXPLORED` is earned only by a complete scope-level scan. A targeted query
   may retrieve and preserve the event without establishing scope coverage.
2. A provider partition and a provider operation are different. An EDR
   `process_tree` endpoint is an operation; a dataset, tenant, endpoint
   collection or stream is a scope only when the provider treats it as a data
   partition. `ProviderOperation.scope_ids` expresses the relationship.
3. `EvidenceRequirement` is versioned but extensible. An unregistered
   requirement becomes `UNSUPPORTED_REQUIREMENT`, never an invented query.
4. The “no OTHER” rule is strict: preserve `native_type`, allow
   `semantic_type=None`, and retain the record as `UNMAPPED` evidence.
5. `UNQUERYABLE` is in the coverage denominator; `UNKNOWN_SOURCE` is outside
   it. Requirement coverage and scope coverage are reported separately.
6. Automatic partition discovery is optional. A static manifest is acceptable
   only as a declared deployment boundary; it cannot claim visibility beyond
   that boundary.
7. The literature verification status is no longer “deferred”: the official
   OCSF, OpenTelemetry, MITRE Data Components, Splunk and Suricata documents,
   plus the Matryoshka, Sieve, SynRAG and Cyber Defense Benchmark papers, are
   recorded in `03` with the level of verification actually performed. They
   motivate the separation of native addressability, query capability and
   semantics; they do not prove production completeness for this project.

The review remains a rationale document. `01` and `02` are the active
contracts; any older family-centric wording in this review is superseded by
this errata.
