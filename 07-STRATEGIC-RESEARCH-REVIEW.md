# 07 — Phản biện chiến lược: tính khoa học, chi phí, khả năng mở rộng

## Kết luận điều hành

**Không thiếu tên paper; thiếu bằng chứng độc lập rằng các mắt xích ghép lại giải quyết bài toán tốt hơn phương án đơn giản. Không thiếu giới hạn từng lời gọi; thiếu mô hình tổng công việc và chi phí trên một vụ điều tra giải quyết đúng.**

Khuyến nghị: giữ typed QueryIntent, read-only execution, evidence ledger, phân biệt UNKNOWN/absence. Thu hẹp phạm vi chứng minh. Catalog đã xác nhận + discovery tăng dần là ứng viên cần so sánh với exhaustive, chưa phải kiến trúc đã được chứng minh tối ưu. Chỉ đổi mặc định sau matched replay đo chất lượng, coverage và tổng chi phí. Không nâng cooccurrence thành semantic proof.

Đây là review tài liệu, không phải audit code hoặc benchmark production. Đã đọc đủ 6 tài liệu gốc. Những `[x]` và kết quả test trong `04` là tuyên bố của tài liệu; không được kiểm chứng bằng artifact thực thi trong lượt này. Không sửa tài liệu gốc.

### Phương pháp research và giới hạn

Agent-Reach CLI không có trên PATH. Đọc README chính thức; dùng trực tiếp upstream Jina Reader (`https://r.jina.ai/URL`) theo cách vận hành dự án mô tả, bổ sung HTTP trực tiếp cho arXiv. Không cài Agent-Reach, không cấu hình cookie. Exa search lỗi; Google gặp CAPTCHA; một Bing result trả nội dung không liên quan và đã bị loại. Research thực hiện bằng truy xuất nguồn gốc, citation chaining và đối chiếu nhiều loại nguồn; không coi đây là systematic literature review đầy đủ.

Nguồn gồm paper hội nghị, preprint, nghiên cứu thực nghiệm schema matching, tài liệu backend và sản phẩm, hướng dẫn an toàn OWASP, kinh nghiệm kỹ thuật vendor. Nguồn vendor chứng minh tính năng được công bố, không chứng minh hiệu quả so với hệ thống này. TESSERACT và selective classification cung cấp nguyên tắc đánh giá, không chuyển nguyên bảo đảm thống kê của classifier sang adaptive agent.[9][11]

## 1. Root cause về cơ sở khoa học

### 1.1 Oracle ngữ nghĩa chưa độc lập — P0

**Bằng chứng nội bộ:** `02:76–83` cho LLM đề xuất relations và acceptance conditions; `06:174–184` dùng validator/verifier để kiểm graph và observation theo contract. `04:24–25,55` nêu schema/provenance tests.

Chuỗi có thể nhất quán nhưng sai: LLM diễn giải sai yêu cầu, tạo điều kiện hợp lệ về kiểu; query trả hàng thật; verifier xác nhận theo chính điều kiện sai đó. `source_request_id` đúng chỉ chứng minh tham chiếu tồn tại. Citation đúng chỉ chứng minh hàng tồn tại. Cả hai không tự chứng minh yêu cầu đã được diễn giải đúng.

Ví dụ phản thực: hỏi “ai thực sự truy cập domain”, graph thành “máy nào phân giải domain”. DNS row thật không đủ xác nhận hành vi truy cập của người. Đây là trường hợp test đề xuất, không phải lỗi đã tái hiện trong code.

Nghiên cứu schema matching dùng ETL được kiểm tra thủ công để xây ground truth semantic mappings độc lập; không lấy mapping model sinh làm chuẩn.[8]

**Hướng xử lý:** acceptance/proof rules thuộc registry được review độc lập, có version, nguồn semantics, phạm vi và giới hạn. LLM chọn/đề xuất rule, không tự cấp quyền chứng minh. Quan hệ mới chưa có rule chỉ phục vụ exploration hoặc chờ xác nhận. Đánh giá request-to-graph riêng bằng required/forbidden claims do chuyên gia gán.

### 1.2 Cooccurrence không chứng minh meaning — P0

**Bằng chứng nội bộ:** `02:113–149` có probe `cooccurrence`; `01:127–131` và `04:39–42` materialize capability sau probe. Tài liệu đã tách capability khỏi incident evidence, nhưng chưa chỉ rõ chứng cứ độc lập nào cấp quyền `relation_observable`.

Person và endpoint cùng hàng có thể là actor/target, owner/observer, sensor/client, hoặc chuỗi được nhắc trong payload. Primitive type và field ID hợp lệ không giải quyết khác biệt này. Nếu mapping sai được cache, lỗi có thể tái sử dụng trên nhiều hunt.

**Hướng xử lý:** cooccurrence mặc định `retrieval_only`. Nâng proof mode chỉ khi có provider contract đã xác nhận hoặc controlled-event replay với ground truth độc lập. Tách ba trạng thái: cấu trúc hợp lệ, truy xuất được, ngữ nghĩa được xác nhận. Schema không đổi vẫn có thể đổi semantics; cần parser/proof-contract version và freshness checks.

### 1.3 “Không hard-code scenario” bị mở rộng thành “không dùng tri thức kiểm chứng sẵn” — P1

**Bằng chứng nội bộ:** `01:35–45`; `02:161–164`; `03:49`. Tránh keyword ép đường điều tra là hợp lý. Nhưng curated provider semantics không đồng nghĩa keyword routing. Compiler có thể dùng capability đã chứng nhận mà vẫn dựng plan theo mục tiêu, không viết sẵn câu chuyện điều tra.

Nghiên cứu Maxam phỏng vấn 11 threat hunters, ghi nhận quy trình đa dạng và khó khăn duy trì automation; không suy ra rằng mọi hệ thống nên loại bỏ workflow hoặc domain contracts.[7] AIQL sử dụng domain-specific model, primitives và tối ưu query theo semantics; không phải hệ thống phi tri thức miền.[18]

**Hướng xử lý:** giữ cấm story expansion không có căn cứ; cho phép reusable, tested capability/proof contracts. Đây là tri thức được kiểm chứng, không phải câu trả lời đóng hộp.

### 1.4 Evaluation nằm sau quá nhiều quyết định thiết kế — P0

**Bằng chứng nội bộ:** `04:120–131` chưa hoàn thành labels, metrics, cross-dataset replay; nhiều phần architecture đã được cố định và đánh dấu hoàn thành trước đó.

Chưa có bằng chứng định lượng rằng dynamic profiler tốt hơn curated mappings, graph planner tốt hơn NL-to-query có guardrails, hoặc replan đáng chi phí. Paper có thể làm nền cho giả thuyết; không thay ablation. SoK về ML security chỉ rõ shortcut correlations, test-data snooping và baseline yếu có thể tạo kết quả gây hiểu nhầm.[10]

**Hướng xử lý:** chuyển từ “hoàn thành kiến trúc rồi đánh giá” sang “chọn kiến trúc bằng thí nghiệm”. Chốt baseline và final holdout trước lần chỉnh prompt/rules tiếp theo. Tách theo campaign, tenant, thời gian, schema family; không random-split log rows của cùng vụ. TESSERACT cho thấy future knowledge và lệch cửa sổ thời gian có thể làm sai đánh giá trong malware classification; áp dụng nguyên tắc kiểm soát thiên lệch, không bê metric hay tỷ lệ dữ liệu sang SIEM.[9]

### 1.5 Abstention có thể che độ hữu ích thấp — P0

**Bằng chứng nội bộ:** `01:179–183,280–289` cho phép narrowing, inconclusive và budget stop; `06:260–267` chưa định nghĩa decision-coverage denominator.

Hệ thống có thể đạt precision cao bằng cách chỉ trả ca dễ. Telemetry coverage khác **decision coverage**: tỷ lệ yêu cầu đủ điều kiện mà hệ thống thực sự giải quyết. Selective classification dùng risk–coverage curve để biểu diễn trade-off từ chối và lỗi; nguyên tắc này hữu ích, không có nghĩa adaptive agent được hưởng cùng risk guarantee.[11]

Báo đồng thời: correctness trên answered subset; resolved/eligible requests; correctly resolved/all requests; malicious-campaign recall; unresolved rate; timeout/parse failure; số phút analyst. Mọi run thất bại vẫn vào chi phí. Không biến `INCONCLUSIVE` thành `BENIGN` để tính metric.

### 1.6 Transition, dependency và causality phải tách — P1

`03:54`, `04:105` đã ghi causality là nghĩa vụ riêng; khoảng thiếu là định nghĩa và ground truth của nghĩa vụ đó. Cùng artifact, timestamp có thứ tự và state/action roles chưa loại concurrent writer, ID reuse, common cause hoặc clock skew.

SLEUTH xây dependency từ audit operations như read/write có dataflow, không từ mọi cặp field đồng hiện.[12] Dùng nhãn riêng: observed transition, provenance dependency, causal attribution. Chỉ cấp nhãn cuối khi có chứng cứ và giả định tương ứng; graph agreement với heuristic sinh chính graph không phải causal ground truth.

## 2. Root cause về chi phí và scalability

### 2.1 Exhaustive profiling nhân tổng công việc — P0

**Bằng chứng nội bộ:** `01:156–163`; `02:90–104`: mỗi unresolved relation lên lịch mọi source và mọi field. Context-sized batching chỉ giới hạn mỗi prompt. Không giới hạn tổng tokens, probes hoặc wall time. Lên lịch đủ không có nghĩa đã xử lý đủ; xử lý đủ không bảo đảm hiểu đúng.

Với R requirement signatures chưa cache, S sources, F_s fields/source: số lần phơi bày field tăng theo `R × Σ F_s`. Số calls thực còn phụ thuộc batch packing, prompt overhead, repairs và cache-hit theo batch.

**Minh họa toán học, KHÔNG phải benchmark hay báo giá.** Giả định cold cache, mỗi field 12 token, mỗi call chứa tối đa 8.000 token profile; bỏ overhead/output/repair, có thể đóng gói field tự do. Khi ấy lower bound số calls là `R × ceil(S × F × 12 / 8000)`.

| Sources | Fields/source | Relations | Profile payload tokens | Calls tối thiểu theo giả định |
|---:|---:|---:|---:|---:|
| 20 | 40 | 6 | 57.600 | 12 |
| 200 | 80 | 6 | 1.152.000 | 144 |
| 1.000 | 100 | 8 | 9.600.000 | 1.200 |

Đã tính bằng Python; inputs/results lưu `research/cost_scenarios.json`. Chưa có dữ liệu để chọn hàng nào đại diện deployment thật.

MDB-Link dùng global column index, shortlist database và budget-aware reranking, không đưa toàn bộ database collection vào mọi lời gọi LLM; đây là preprint text-to-SQL, không chứng minh trực tiếp hiệu quả trên cybersecurity.[1] Toolshed cũng nghiên cứu trade-off retrieval accuracy, agent performance và token cost; không cung cấp bảo đảm recall cho telemetry của dự án.[3]

**Đề xuất:** catalog đầy đủ để audit; online shortlist theo capability/relation; progressive widening khi thiếu proof hoặc còn ngân sách. Giữ danh sách nguồn chưa xem. Exhaustive mode dùng làm offline oracle/recall audit hoặc run được phê duyệt riêng. Không dùng shortlist để kết luận âm toàn scope.

### 2.2 Cache chưa có hợp đồng nhất quán — P0

`02:109–110,302–306` mô tả once-per-key/one-call-plus-repair nhưng `02:90–104` yêu cầu nhiều batches. Cần phân biệt job profiling và calls của từng batch. Completion manifest phải chỉ rõ batch nào xong; không đánh dấu cache complete từ batch đầu.

Fingerprint quá rộng, gồm counts/sketches biến động, có thể làm mọi run cold. Fingerprint quá hẹp, chỉ tên/type, bỏ sót semantic/permission changes. Checklist đã nhắc permission state; vấn đề là các mô tả chưa thống nhất, không phải hoàn toàn thiếu nó.

Tách structural schema version, effective authorization scope, proof-contract/parser version và observability freshness. Cache theo tenant/principal hoặc authorization digest, scope, requirement + qualifiers; output model/prompt-dependent phải có version. Warm capability cache không cấp phép reuse incident conclusion hoặc negative evidence qua time window mới. Đo hit rate thật trước khi hứa tiết kiệm.

### 2.3 Census không mặc nhiên miễn phí — P0

`02:56–63` yêu cầu event counts, null rates, inferred types và sketches trước hunt. Với schema-on-read, các trường này có thể cần content scans. Metadata cache hit không khiến retrieval evidence miễn phí.

Dùng provider catalog trước; refresh source-local theo version/TTL; sample chỉ khi cần. Ghi exact/estimated/unknown, sampling frame và thời điểm. Đo riêng census queries, bytes/CPU, latency. Không gọi field không xuất hiện trong sample là không tồn tại.

### 2.4 LIMIT không đồng nghĩa bounded backend work — P0

`02:143–149,202–212` yêu cầu row/time/scan bounds nhưng chưa chứng minh mọi adapter có hard cap/cancel thực. Aggregation, join, sort có thể làm nhiều việc trước khi trả ít hàng. Client timeout không chứng minh backend đã dừng.

Microsoft tài liệu hóa row cap, tenant CPU allocation và timeout thành các giới hạn riêng ở **older Advanced Hunting API**. Đây là ví dụ về các trục tài nguyên độc lập, không áp nguyên quota của API đó cho Graph API, Splunk hay Sentinel.[14]

Adapter phải khai báo estimator, hard cap, cancellation và provider stats thực có. Không giả định dry-run là cost proof. Query không đáp ứng hard budget phải bị từ chối hoặc đi chế độ có phê duyệt với giới hạn được nói rõ. Dùng concurrency quota theo tenant/provider, fair queue, backpressure, cancellation verification, retry budget. Tăng workers không tăng quota backend.

### 2.5 “Provider-neutral” không xóa chi phí integration — P1

Mỗi backend vẫn cần RBAC, pagination/completeness, grammar, escaping, identity/time semantics, proof extractors, query cost, cancellation và replay fixtures (`02:352–368`; `04:75–81,133–150`). Native-query fallback thêm diện tích phải bảo trì và tấn công.

Giữ một backend cùng vài proof contracts trước. Trì hoãn native fallback nếu QueryIntent subset giải quyết workload mục tiêu. Unsupported phải được báo thật, không âm thầm chạy raw query. Không cần graph database hoặc microservices chỉ vì data model tên là graph.

## 3. Mô hình chi phí phải dùng

Không có tariff, workload hay telemetry thực; **chưa thể kết luận USD/hunt, số tenant tối đa hoặc SLA**.

`C_run = C_census + C_LLM + C_probes + C_hunt_queries + C_storage/egress + C_control_plane`.

`C_LLM = Σ(uncached_input_tokens × input_rate + cached_input_tokens × cached_rate + output_tokens × output_rate)`; quy đổi đúng đơn vị tariff. Backend capacity-priced cần ghi resource consumption và opportunity cost, không tự đặt USD/GB. Không đếm hai lần cached tokens.

`TCO = licenses/platform + usage + integration/maintenance labor + oncall + analyst review + compliance`.

**Chỉ số quyết định:** `tổng chi phí toàn cohort / số case giải quyết đúng`; kèm số phút analyst/case, decision coverage, safety errors. So sánh incremental cost khi khách đã mua SIEM với all-in cost khi triển khai mới. Không trộn hai cơ sở giá.

Dữ liệu cần trước quyết định scale:

| Nhóm | Dữ liệu thiếu |
|---|---|
| Nhu cầu | Ai mua, ai dùng, tác vụ lặp lại, yêu cầu/giờ, mức chấp nhận chờ và inconclusive |
| Telemetry | Sources/fields, GB/ngày, retention, cardinality, source churn, permissions, event loss, clock skew |
| Semantics | Provider mappings độc lập, ambiguous/forbidden relations, khả năng chứng minh negative |
| Ground truth | Campaign manifests, observation IDs, required claims, answer aliases, adjudication disagreements |
| Cost | Actual tokens/calls, repairs, census scans, probe scans, cache hits, queue/runtime, provider billing |
| Vận hành | Concurrent tenants, noisy-neighbor behavior, cancellation, authorization revocation, audit retention |
| Giá trị | Analyst baseline time, time saved sau review, unresolved follow-up cost, willingness to pay |

## 4. Rủi ro lớn nhất, chi phí cơ hội, điểm bị khai thác

**Rủi ro kỹ thuật lớn nhất:** semantic mapping sai nhưng đi qua nhiều lớp kiểm tra và được trình bày như “verified”. Audit trail đẹp có thể khuếch đại niềm tin sai. Đây là failure mode thiết kế cần test, chưa phải incident đã quan sát.

**Rủi ro sản phẩm lớn nhất:** hệ thống an toàn bằng cách không trả lời ca khó, analyst vẫn làm phần lớn công việc; chi phí automation cộng thêm thay vì thay thế.

**Chi phí cơ hội:** thời gian làm universal schema discovery, multi-backend parsers, raw query fallback và thêm graph contracts cạnh tranh trực tiếp với thời gian tạo ground truth, reusable proof contracts và một pilot đo lợi ích. Kiến trúc chỉ được giữ phần phức tạp khi ablation chứng minh giá trị. Hướng dẫn kỹ thuật Anthropic cũng khuyên chỉ tăng complexity khi kết quả cải thiện đo được; đây là kinh nghiệm vendor, không phải định lý.[6]

### Đối thủ thương mại có thể khai thác

| Đối thủ | Tính năng đã công bố | Điểm yếu chiến lược của dự án có thể bị nhắm vào |
|---|---|---|
| Microsoft Defender | Schema/table discovery, joins, permissions-aware read-only hunting assistant.[13] | NL-to-query và schema awareness không đủ là khác biệt; khách hỏi vì sao mua thêm lớp mới |
| Microsoft Sentinel | Hypothesis, investigation, validation, bookmarks và evidence workflow.[15] | Graph/hypothesis loop không tự thành lợi thế khó sao chép |
| Elastic Security | Assistant cho alert investigation, incident response, query generation.[16] | Demo chatbot không đủ biện minh switching/integration cost |
| Google SecOps | Natural language thành query trên UDM; nguồn hướng dẫn yêu cầu prompt tiếng Anh.[17] | Sản phẩm có schema chuẩn có thể chọn phạm vi hẹp hơn; dự án phải chứng minh lợi ích unknown-schema xứng đáng chi phí |

Không có matched benchmark để kết luận đối thủ nhanh/rẻ/chính xác hơn. Các dòng cuối là suy luận về thế cạnh tranh, không phải số đo hoặc tuyên bố vendor có cùng verifier.

**Lợi thế tiềm năng đáng thử:** lớp evidence/coverage kiểm chứng trên backend khách đã có; trả rõ điều gì chứng minh được, điều gì chỉ là candidate, vì sao không thể kết luận âm. Tài sản khó sao chép hơn pipeline là corpus proof contracts, adapter conformance fixtures và benchmark đa tenant được gán nhãn độc lập. Wedge này vẫn cần customer validation.

### Adversary kỹ thuật có thể khai thác

Role-spoofing trong field samples; source/schema poisoning; field cùng type nhưng khác nghĩa; identity ambiguity tạo fan-out/narrowing; payload khiến profiler/replanner đốt ngân sách; schema churn gây cache miss; prompt injection trong log hoặc CTI. OWASP xác định indirect prompt injection qua nội dung bên ngoài và khuyến nghị least privilege, kiểm output, adversarial testing; RAG không tự loại rủi ro này.[4]

Security gates tối thiểu: tenant-scoped authorization ở dispatch lẫn evidence read; secret/redaction boundary; data minimization; cache isolation; permission revocation tests; không cho model đổi scope/budget/proof authority. Không chỉ kiểm prompt injection ở request đầu.

## 5. Hướng kiến trúc đề xuất

Không thay toàn bộ hệ thống. Giữ graph/ledger như mô hình logic, không mặc định một database/service cho mỗi graph.

1. **Control plane ngoài hot path:** census incremental; semantic catalog và proof contracts có version; đánh giá schema/permission changes; unknown mappings chưa được chứng nhận.
2. **Hunt hot path:** frozen request và budget; semantic proposal; kiểm nghĩa vụ bằng approved contracts; retrieve capabilities; compile bounded QueryIntent; execute; evidence update; deterministic contract verification; trả answer hoặc uncertainty.
3. **Discovery theo nhu cầu:** chỉ bật khi capability/proof gap còn ảnh hưởng câu hỏi; retrieve shortlist, probe, progressive widening. Cooccurrence không tự nâng proof mode. Ghi unexamined coverage.
4. **Exhaustive audit riêng:** đo phần shortlist bỏ sót, kiểm recall trên labelled replay; không ép mọi production hunt phải trả phí quét toàn catalog.
5. **Native fallback:** để sau, chỉ supported grammar subset và provider có cost/security controls thật. Không coi đây là điều kiện phải có của MVP.

## 6. Chương trình kiểm chứng và thứ tự ưu tiên

### P0 — Chọn câu hỏi khoa học trước, không thêm provider

Chốt một workload pilot cụ thể với analyst, một backend, một tập relations cần chứng minh. Luận điểm đề xuất:

> Với telemetry/schema chưa thấy và ngân sách cố định, capability retrieval có kiểm soát cùng proof contracts độc lập giảm kết luận thiếu căn cứ so với baseline, mà không làm giảm decision coverage hoặc tăng tổng chi phí vượt mức chấp nhận của người dùng.

Đây là giả thuyết để bác bỏ, không phải claim thành tích.

### P0 — Đóng băng baseline và oracle

Cùng questions, telemetry, permissions, model và budget:

- B0: curated queries/contracts và analyst review.
- B1: NL-to-query hoặc typed-intent đơn giản với cùng safety envelope; không dynamic profiling/replan.
- B2: kiến trúc v7 exhaustive.
- B3: curated capability catalog + adaptive discovery.
- Oracle ablation: mappings/goal graph do chuyên gia xác nhận, dùng để phân rã lỗi, không quảng bá như sản phẩm deployable.

Ablation giữ input và budget như nhau: actual vs oracle goal graph; actual vs oracle mapping; no replan vs bounded replan; exhaustive vs shortlist+widening. So sánh tại cùng decision coverage và thêm đường cost–quality; không chỉ so F1 trung bình.

### P0 — Bộ phản thực đánh trúng authority gap

Role swap; visited/resolved; owner/observer; misleading source names; semantic drift với schema không đổi; thiếu telemetry; permission revoked; complete-empty; partial response; high-cardinality binding; log injection. Ground truth không được sinh từ chính heuristics verifier đang kiểm.

### P1 — Đo scale và đơn vị kinh tế

Cold tenant; warm repeated requirement; qualifier mới; source-local/global schema churn; concurrent cold starts; noisy neighbor; query timeout/cancellation. Báo p50/p95 latency, queued time, tokens, scans/CPU, actual hit rate, budget stops, correct resolutions, analyst minutes. Payload giả lập có thể đo orchestrator overhead, không thay backend replay cho scan cost.

### P1 — Pilot đánh giá analyst

Cho analyst giải cùng loại case theo thứ tự cân bằng, không biết đáp án trước. Tính tổng thời gian gồm review, sửa sai, follow-up sau inconclusive. Chốt affordability/SLA/coverage floor từ nhu cầu thật trước final holdout. Không lấy ngưỡng F1 tùy ý làm scientific constant.

### P2 — Chỉ mở rộng khi có bằng chứng

Thêm backend nếu portability là nhu cầu đã xác nhận và adapter conformance pass. Giữ dynamic discovery nếu nó mở được case quan trọng mà curated path bỏ lỡ với tổng chi phí chấp nhận được. Nếu oracle mapping vẫn không cứu performance, dừng đầu tư profiler; xem lại semantic goal, telemetry hoặc chính workload. Nếu curated baseline ngang bằng với ít chi phí hơn, dùng baseline đó.

**Quyết định ưu tiên:** đóng semantic authority gap và xây benchmark độc lập trước. Sau đó quyết định exhaustive/adaptive bằng số đo. Không viết thêm kiến trúc để thay việc đo.

## 7. Tái thẩm định chiến lược — kết luận thay thế về thứ tự triển khai

**Chưa thể gọi đây là chiến lược tối ưu.** Review trước xác định các rủi ro hợp lý nhưng nhảy từ chẩn đoán sang chọn catalog + adaptive discovery khi chưa đo workload. Phần này ưu tiên hơn những câu khuyến nghị thay mặc định ở trên. Không thay kiến trúc production trước khi kiểm chứng.

### Những điểm phải sửa trong chính khuyến nghị

- **Không mặc định mục tiêu thương mại.** Tài liệu hiện nói thesis; nếu mục tiêu chính là nghiên cứu, scientific contribution và out-of-distribution evaluation quan trọng hơn willingness-to-pay. Chốt mục tiêu chính và ràng buộc trước khi chọn pilot.
- **Không coi curated contracts là oracle tuyệt đối.** Chúng vẫn có lỗi, chi phí tác giả/review, giới hạn phiên bản và rủi ro overfit. Cần nhãn độc lập với tác giả rules, lưu bất đồng và test chưa thấy. Registry ban đầu chỉ cần cấu hình/versioned files; không xây service mới.
- **Không bắt buộc xây đủ bốn baseline.** Đầu tiên tận dụng baseline đơn giản và đường hiện có chạy được. Oracle ablation dùng trên replay nhỏ để tìm bottleneck. Chỉ triển khai adaptive comparator nếu profiling thực sự là phần tốn kém hoặc gây budget stops. Không hoàn thiện v7 chỉ để làm baseline.
- **Không giả định exhaustive luôn thua.** Catalog nhỏ, ít relations, schema ổn định, cache reuse cao hoặc yêu cầu coverage cao có thể khiến exhaustive đơn giản và phù hợp hơn. Adaptive có retrieval miss, indexing/reranking và maintenance cost. So sánh cold/warm và phân bố workload thật.
- **Không lấy cost/correct-case làm mục tiêu duy nhất.** Nó có thể ưu tiên ca dễ. Đóng băng workload mix; báo theo độ khó và mức nghiêm trọng, đặt floor cho recall/decision coverage, ceiling cho kết luận sai nghiêm trọng và latency; sau đó tối thiểu hóa total cost. Nếu không đáp ứng ràng buộc, không chọn chỉ vì rẻ.
- **Một backend chỉ giới hạn implementation pilot, không đủ chứng minh generality.** Nếu portability là luận điểm nghiên cứu, cần held-out schema/provider fixtures sớm và kiểm adapter thứ hai có mục tiêu trước khi tuyên bố đa backend. Không mở rộng tích hợp đại trà.
- **Không bỏ qua phương án không xây agent mới.** Nếu mục tiêu vận hành, benchmark cả workflow/query library hiện có hoặc thin verifier/report layer. Nếu chúng đạt yêu cầu thì dừng ở đó. Đối với thesis, chúng là baseline chứ không tự thay thế đóng góp nghiên cứu.

### Thứ tự quyết định tối giản

1. Xác định mục tiêu chính, người dùng, một workload đại diện và điều kiện đạt/không đạt. Tránh chọn riêng ca thuận lợi cho giải pháp.
2. Kiểm inventory code/replay sẵn có; chạy ca hợp lệ, phản thực và thiếu telemetry trên đường hiện có. Tách planning/mapping/execution/verification errors, đo thời gian và tài nguyên từng bước. Không có runnable path thì dựng vertical slice nhỏ nhất, không toàn framework.
3. Dùng goal/mapping do chuyên gia xác nhận trên cùng replay để xác định nút thắt. Nếu nguồn không chứa thông tin cần thiết, xử lý data access/observability trước AI.
4. Sửa tối thiểu đúng nút thắt: sai proof authority thì khóa promotion; query scan lớn thì tối ưu query/backend; profiler dominates thì thử reuse/batching/adaptive; analyst review dominates thì thử evidence presentation. Không chọn trước kết quả.
5. Freeze phương án, ngưỡng, budget, cache policy và test split. Chạy paired holdout/repeated model runs; uncertainty tính theo đơn vị case/campaign độc lập, không coi log rows hay repeated calls là mẫu độc lập. Quy mô kiểm chứng dựa vào mức rủi ro/effect cần phát hiện, không một con số test tùy ý.
6. Giữ giải pháp đơn giản nhất thỏa constraints trên workload đã định. Nếu nhiều phương án không trội hẳn, báo Pareto trade-off thay vì tuyên bố một tối ưu toàn cục. Chỉ mở rộng sau evidence gate.

### Điều kiện đảo quyết định

| Quan sát thực tế | Quyết định hợp lý |
|---|---|
| Hiện có đáp ứng yêu cầu; agent không giảm effort hoặc lỗi | Không xây thêm agent; giữ baseline hoặc thin verifier |
| Semantic errors là chính | Proof contracts + independent labels trước discovery optimization |
| Telemetry thiếu thông tin | Sửa instrumentation/access; không tăng model/replan |
| Census/backend scan là chi phí chính | Incremental metadata và physical query optimization trước token tuning |
| Exhaustive rẻ và đạt coverage trên catalog mục tiêu | Giữ exhaustive; không thêm retrieval subsystem |
| Profiling dominates và adaptive giữ quality/coverage ở total cost thấp hơn | Chuyển mặc định sang adaptive, giữ audit/fallback |
| Unknown-schema cases quan trọng nhưng curated baseline bỏ lỡ | Đầu tư dynamic discovery có kiểm soát và OOD evaluation |

Kết quả lượt này là **validation logic và sửa thứ tự quyết định**, không phải empirical validation tối ưu chi phí/chất lượng. Chưa có workload, runtime traces, tariff, labels và yêu cầu chấp nhận nên chưa thể xếp hạng định lượng các phương án.

## Sources

[1] https://arxiv.org/abs/2608.09588
    > "MDB-Link first encodes the question"
    > "This module identifies the database whose schema contains the information needed to answer the input question."
[3] https://arxiv.org/abs/2410.14594
    > "Furthermore, by varying both the total number of tools (tool-M) an Agent has access to and the tool selection threshold (top-k), we address trade-offs between retrieval accuracy, agent performance, and token cost."
[4] https://genai.owasp.org/llmrisk/llm01-prompt-injection
    > "Indirect prompt injections occur when an LLM accepts input from external sources, such as websites or files."
[6] https://www.anthropic.com/engineering/building-effective-agents
    > "Agentic systems often trade latency and cost for better task performance, and you should consider when this tradeoff makes sense."
[7] https://www.usenix.org/conference/usenixsecurity24/presentation/maxam
    > "We obtained access and interviewed 11 threat hunters associated with the U.S. government's Department of Homeland Security."
[8] https://arxiv.org/html/2407.11852v1
    > "We use this ETL specification to manually identify all semantically valid 1:1 matches that will serve as the ground truth."
[9] https://www.usenix.org/system/files/sec19-pendlebury.pdf
    > "C2) Temporal gw/mw windows consistency. In every testing slot of size ∆, all test objects must be from the same time window:"
[10] https://www.usenix.org/system/files/sec22-arp.pdf
    > "Artifacts unrelated to the security problem create shortcut patterns for separating classes."
[11] https://proceedings.neurips.cc/paper/2017/file/4a8423d5e91fda00bb7e46540e2b0cf1-Paper.pdf
    > "The entire performance profile of such a classifier can be specified by its risk-coverage curve, defined to be risk as a function of coverage [5]."
[12] https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-hossain.pdf
    > "Object event records are maintained only for a subset of events: specifically, events such as read and write that result in a dataflow."
[13] https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-security-copilot
    > "Discovery follows your own permissions, so the assistant only reaches data that you can already query in advanced hunting. It runs read-only queries and can't run commands that change data or configuration."
[14] https://learn.microsoft.com/en-us/defender-xdr/api-advanced-hunting
    > "Results can return up to 100,000 rows."
    > "Each tenant is allocated CPU resources, based on the tenant size."
[15] https://learn.microsoft.com/en-us/azure/sentinel/hunting
    > "With hunts in Microsoft Sentinel, seek out undetected threats and malicious behaviors by creating a hypothesis, searching through data, validating that hypothesis, and acting when needed."
[16] https://www.elastic.co/docs/solutions/security/ai/ai-assistant
    > "Elastic AI Assistant for Security helps you interact with your Elastic Security data and assists with tasks such as alert investigation, incident response, and query generation."
[17] https://cloud.google.com/chronicle/docs/investigation/generate-udm-search-queries-gemini
    > "Using the Google SecOps search feature, you can enter a natural language query about your data, and Gemini can translate this into a search query to run against UDM events."
[18] https://www.usenix.org/conference/atc18/presentation/gao
    > "an optimized query engine based on the characteristics of the data and the semantics of the queries to efficiently schedule the query execution."
