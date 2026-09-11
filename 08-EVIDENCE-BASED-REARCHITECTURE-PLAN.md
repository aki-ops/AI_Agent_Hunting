# 08 — PHƯƠNG ÁN TÁI KIẾN TRÚC VÀ KẾ HOẠCH TRIỂN KHAI CÓ KIỂM CHỨNG

**Ngày chốt đề xuất:** 2026-09-11  
**Trạng thái:** kiến trúc ứng viên để triển khai và thực nghiệm; chưa thay thế
`01`–`06` cho tới khi vượt qua các evidence gate trong tài liệu này.  
**Phạm vi trước mắt:** một vertical slice chạy thật trên Splunk. Provider khác
được hoãn, nhưng hợp đồng không được gắn cứng với Splunk, `botsv2`, Mallory,
email, PowerPoint, TOR, web hay bất kỳ đáp án cụ thể nào.

## 1. Quyết định điều hành

Phương án khả thi nhất hiện tại là một **Contract-Grounded Progressive Hunt
Graph**: LLM hiểu yêu cầu và đề xuất graph; runtime từng bước tìm nguồn, sinh
query và diễn giải evidence; nhưng LLM không được tự cấp cho chính nó quyền
khẳng định một quan hệ là đúng.

```text
Yêu cầu tự nhiên
  -> LLM biên dịch GoalGraph + AnswerContract
  -> kiểm tra graph và provenance
  -> chọn goal đang sẵn sàng
  -> tìm capability theo progressive frontier
  -> bind entity/value hoặc hỏi người dùng nếu còn mơ hồ
  -> QueryIntent
       -> compiler xác định, nếu hỗ trợ
       -> SPL do LLM đề xuất trong vùng cách ly, nếu thật sự cần
  -> kiểm tra an toàn + chạy query có giới hạn
  -> observation -> fact -> candidate evidence
  -> ProofContract xác minh quan hệ và answer slot
  -> tiếp tục / mở rộng / hỏi / dừng theo trạng thái có thể kiểm tra
  -> báo cáo answer, quá trình, evidence, query, coverage và cost
```

Đây không phải kiến trúc đã được một paper chứng minh tối ưu toàn cục. Nó là
phương án tổng hợp có căn cứ tốt nhất cho mục tiêu của dự án ở thời điểm hiện
tại. Mỗi phần kế thừa một kết quả đã có; phần ghép nối và policy cụ thể là đóng
góp kỹ thuật của thesis và phải được đánh giá bằng replay/holdout.

Ba quyết định không thương lượng:

1. **LLM là semantic planner, không phải semantic oracle.** Model có thể đề xuất
   goal, source, field, query và lời giải thích. Chỉ validator, adapter và
   ProofContract đã kiểm thử mới được thay đổi trạng thái chứng minh.
2. **Không full-schema prompt và không fixed Top-K một lần.** Dùng source catalog
   ngoài hot path và mở rộng một frontier theo từng vòng. Nguồn chưa xét luôn
   được ghi là coverage gap; shortlist không được dùng để chứng minh “không có”.
3. **Không tự chọn candidate khi bằng chứng chưa đủ.** Nếu có nhiều account,
   host, IP hoặc artifact cùng hợp lệ và query phân biệt tiếp theo không thể
   giảm mơ hồ trong budget, agent phải hỏi người dùng hoặc dừng
   `NEEDS_DISAMBIGUATION`.

## 2. Vì sao đây là hướng thực tế nhất

### 2.1 Bằng chứng nghiên cứu và giới hạn chuyển giao

| Nguồn | Kết quả có thể dùng | Không được suy diễn quá mức |
|---|---|---|
| ExCyTIn-Bench (ICML 2026) | Điều tra cyber là bài toán nhiều bước, query là action, kết quả là observation; graph cho phép chấm cả bước trung gian. Trên 57 bảng và 7.542 câu hỏi, model tốt nhất trong paper vẫn chỉ đạt reward 0,606.[1] | Graph benchmark được tạo từ alert/entity đã có ground truth; nó không chứng minh LLM tự tìm đúng semantics trên một Splunk chưa biết schema. |
| Cyber Defense Benchmark (technical report 2026) | Khi bỏ gợi ý và yêu cầu săn trực tiếp trên 75k–135k raw events/episode, model tốt nhất chỉ tìm đúng khoảng 3,8% malicious events trung bình.[2] | Đây là technical report/preprint, không phải bằng chứng rằng mọi LLM hunter đều bất khả thi; nó bác bỏ giả định “model mạnh là đủ”. |
| AutoLink (AAAI 2026) | Schema linking nên là quá trình khám phá–kiểm tra–mở rộng lặp, không đưa toàn bộ schema vào một prompt. Paper báo SRR 97,4% trên BIRD-Dev và 91,2% trên Spider 2.0-Lite.[3] | Paper vẫn dùng các tham số top-n/top-m và là text-to-SQL. Dự án chỉ kế thừa progressive exploration; policy frontier không fixed Top-K bên dưới là thiết kế mới phải tự đo. |
| MDB-Link (preprint 2026) | Dùng global schema index, shortlist và budget-aware reranking thay vì phơi toàn bộ collection cho LLM.[4] | Chưa phải kết quả threat hunting và là preprint; chỉ hỗ trợ quyết định giảm context. |
| Toward Autonomous SOC Operations (PMLR 2026) | Query generation được cải thiện bằng syntax constraints, metadata retrieval và documentation-grounded prompting cho nhiều SIEM.[5] | BLEU/ROUGE của query không chứng minh denotation hay semantics đúng. Ta chỉ dùng nguyên tắc constrained generation, không dùng text overlap làm acceptance gate. |
| Kestrel | Threat hunting có thể mô hình hóa như tìm subgraph/subset lặp; tài liệu thừa nhận telemetry thật có thể rời rạc và graph không đầy đủ.[6] | Kestrel không chứng minh graph do LLM sinh là đúng và không thay ProofContract. |
| AIQL | Typed, domain-specific primitives tách logic điều tra khỏi tối ưu thực thi và giúp query investigation có cấu trúc.[7] | Không nên biến primitive thành playbook đóng theo từng câu chuyện. |
| OCSF | Cung cấp taxonomy, event classes, objects và attribute dictionary có version, vendor-neutral và mở rộng được.[8] | Tên field chuẩn không tự chứng minh direction, ownership, causality hay hành vi của một người. OCSF là vocabulary, không phải proof oracle. |
| Sigma/pySigma | Rule logic có thể tách khỏi backend; processing pipeline ánh xạ logsource, field và môi trường rồi backend sinh query đích.[9] | Sigma chủ yếu là detection/hunting rule. Nó không tự trả lời factual multi-hop question và không chứng minh candidate entity. |
| SLEUTH | Provenance edge chỉ được tạo từ operation có dataflow thực như read/write, không từ mọi cặp field đồng xuất hiện.[10] | Không phải mọi source đều có audit semantics đủ mạnh như provenance log. |
| Selective classification | Hệ thống có quyền abstain phải được đánh giá bằng quan hệ risk–coverage, không chỉ precision trên số case nó chịu trả lời.[11] | Không thể bê nguyên guarantee thống kê sang agent adaptive; ta chỉ kế thừa cách báo coverage và error. |
| Safe tool use (ICSE-NIER 2026) | Tool capability và chuỗi hành động nên có specification cưỡng chế bên ngoài model; an toàn không nên dựa vào model tự hứa.[12] | Đây là hướng mới, không chứng minh verifier cụ thể của dự án là đầy đủ. |
| Splunk REST/Search docs | Search job có `dispatch.max_time`, trạng thái hủy, `scanCount`, `runDuration`, `resultCount` và performance metadata để quản trị chi phí thật.[13] | `head 100` chỉ giới hạn output; không mặc nhiên giới hạn số event backend đã scan. |
| ACES/ACESEvals | Benchmark agent bằng task cấu hình, sandbox, tool execution, checkpoint và scorer; ExCyTIn có tập test/train công khai và chế độ raw-telemetry khó.[14] | Không dùng LLM judge duy nhất làm ground truth; cần scorer xác định cho answer/evidence khi có thể. |

### 2.2 Kết luận khoa học được phép đưa ra

Các nguồn trên hỗ trợ sáu nguyên lý: intermediate graph, iterative exploration,
schema/capability retrieval, typed query, external verification và selective
abstention. Chưa nguồn nào chứng minh tổ hợp cụ thể này tối ưu trên BOTS v2 hay
deployment của dự án. Vì vậy thesis nên phát biểu dưới dạng giả thuyết có thể
bác bỏ:

> Với cùng model, telemetry và ngân sách, graph có proof contract cùng capability
> discovery tăng dần sẽ giảm semantic false support và giảm token/query waste so
> với đường hiện tại, mà không làm giảm decision coverage quá ngưỡng đã chốt.

## 3. Chẩn đoán gốc rễ của hệ thống hiện tại

Các lỗi Mallory/Alice, tự chọn host, query SMTP/LDAP/Sysmon không liên quan,
`head 101` cực rộng và dừng sớm không phải những lỗi rời rạc. Chúng cùng xuất
phát từ chín vấn đề hệ thống:

1. **Graph proposal và proof semantics chưa độc lập.** LLM có thể đề xuất
   `proof_mode=relation_observable`; validator hiện chủ yếu kiểm source/field tồn
   tại. Một cooccurrence probe thành công có thể biến mapping sai nghĩa thành
   capability “VALIDATED”.
2. **Goal chưa phải nghĩa vụ chứng minh.** Một câu mô tả đích có thể tồn tại mà
   không có answer slot, mandatory gates, refutation rule và completeness rule;
   controller vì thế không biết chính xác còn thiếu gì.
3. **Source discovery là exhaustive prompt batching.** Chia 25 source/617 field
   thành nhiều batch chỉ giảm kích thước một call, không giảm tổng context và
   không bảo đảm relation semantics.
4. **`ContextRegion`/route còn mang tri thức tình huống cố định.** Email, file,
   web, process hoặc tên source có thể vô tình trở thành action selector. Case
   khác từ vựng sẽ lạc đường, còn case giống từ khóa bị áp playbook.
5. **Entity binding thiếu trạng thái mơ hồ chính thức.** Runtime có thể chọn một
   host có vẻ hợp lý thay vì giữ tập candidate và chứng minh relation.
6. **Query generation không tách exploration và proof.** Query rộng có thể hữu
   ích để dò dữ liệu nhưng lại được xử lý như query trả lời; row limit bị nhầm
   với backend-work/completeness limit.
7. **Evidence authority còn lẫn với retrieval success.** “Có row” chứng minh
   query chạy và tìm được candidate, không chứng minh quan hệ người–máy,
   before–after rename hay causal encryption.
8. **Stop rule không bám AnswerContract.** Agent có thể dừng khi hết action hoặc
   query partial thay vì khi mọi answer slot và mandatory gate đã được xử lý.
9. **Test phần lớn kiểm invariant nội bộ.** Code có thể pass tests do expected
   result lặp lại chính heuristic bị sai; chưa có oracle độc lập cho role swap,
   misleading schema, alternate path và forbidden claims.

## 4. Kiến trúc mục tiêu

Kiến trúc có hai plane. Không cần graph database hay microservice trong MVP;
graph là data model và state machine trong process Python hiện tại.

### 4.1 Control plane — chuẩn bị ngoài mỗi hunt

Control plane quản lý thứ có thể tái sử dụng:

- `ProviderManifest`: provider nào được cấu hình, credential scope, index/source,
  retention, permission, health, query limits và cách hủy job.
- `SourceCard`: một mô tả nhỏ cho từng source/sourcetype gồm field names/types,
  descriptions, sample-value sketches đã redact, time span, cardinality estimate,
  parser/schema version và provenance. Không chứa suy đoán “source này chắc là
  email” nếu chưa có mapping được review.
- `SemanticVocabulary`: entity/value/relation types chung; có thể tham chiếu
  OCSF, ATT&CK hoặc Sigma taxonomy nhưng cho phép `native_unknown`.
- `ProofContractRegistry`: tri thức ngữ nghĩa đã được con người review và test.
- `QueryCompilerRegistry`: compiler/pipeline theo provider; dùng typed intent
  tương tự separation của pySigma, không lưu câu trả lời hay tên nhân vật.
- `CapabilityIndex`: chỉ mục lexical + embedding trên SourceCard để tìm candidate.
  Index hỗ trợ discovery, không cấp quyền proof.
- `EvaluationCorpus`: question, acceptable graph paths, gold answer/evidence,
  forbidden assumptions và split cố định.

Census hot path trước mỗi hunt chỉ kiểm health, permission, time bounds và
fingerprint. Field sampling sâu chạy incrementally khi cache stale hoặc source
đang nằm trên frontier; không chạy `fieldsummary` trên mọi source mỗi request.

### 4.2 Hunt plane — một lần chạy

#### Bước A — đóng băng request và budget

Tạo `HuntRunContext` bất biến:

```text
request_id, request_text_hash, user-supplied facts,
time policy, permitted providers/scopes,
LLM call/token ceiling, provider scan/runtime/query ceiling,
prompt/model/registry versions
```

Agent có thể tự phát hiện provider trong registry và kiểm tra kết nối; nó không
cần người dùng truyền `--provider`. Tuy nhiên nó không được “tự tìm” credential
hoặc backend ngoài những adapter đã cấu hình. Nếu chỉ Splunk khả dụng thì chọn
Splunk vì health/capability, tuyệt đối không fallback sang SQLite/CDB chỉ vì code
có adapter test.

#### Bước B — LLM biên dịch GoalGraph và AnswerContract

Call này chỉ nhận request, vocabulary/JSON schema nhỏ và time policy; **không
nhận toàn bộ source/field catalog và không sinh SPL**.

```text
GoalGraph {
  answer_slots[]: value type + acceptance condition,
  goals[]: atomic obligation,
  dependencies: AND / OR / GATE,
  variables[]: typed, unbound or user-provided,
  qualifiers[]: time/device/ownership/etc.,
  assumptions[]: explicit and non-binding,
  forbidden_inferences[],
  clarification_triggers[]
}
```

Mỗi goal phải truy ngược được về một đoạn trong request hoặc một fact đã xác
minh. Không cho phép “story expansion”: ransomware không tự động kéo theo DNS,
SMTP hay PowerShell nếu các bước đó không cần để lấp answer slot hoặc kiểm tra
một điều kiện bắt buộc.

`MacBook` trong request là qualifier loại thiết bị, chưa phải hostname. `Mallory`
là person label, chưa phải account `mallory.kraeusen`. Những binding đó phải
được tìm và chứng minh sau.

#### Bước C — deterministic graph validation

Validator từ chối hoặc sửa giảm graph nếu:

- đổi tên/thực thể do người dùng nêu, ví dụ Mallory thành Alice;
- answer slot không khớp loại câu trả lời;
- goal không có request span/provenance;
- dependency vòng, GATE không rõ hoặc condition không kiểm được;
- acceptance rule đòi field/source cụ thể do LLM tự bịa;
- giả định được nâng thành fact;
- graph tự mở rộng sang một câu chuyện tấn công không cần thiết.

LLM không viết acceptance semantics cuối cùng. Nó chỉ chọn relation/type trong
vocabulary hoặc gắn `NOVEL_RELATION`. Relation mới đi theo đường exploration và
không được kết luận `SUPPORTED` cho tới khi có proof contract/human review.

#### Bước D — lập plan bằng AND/OR/GATE graph

Planner xác định, không phải prompt, duy trì:

- `AND`: tất cả predecessor phải đủ;
- `OR`: bất kỳ đường nào chứng minh cùng output binding đều có thể mở gate;
- `GATE`: goal downstream không chạy nếu đầu vào bắt buộc chưa được bind;
- `OPTIONAL`: chỉ dùng để tăng confidence, không chặn answer;
- `DISCRIMINATOR`: query dùng để giảm nhiều candidate về một candidate.

Cách phân rã theo nhiệm vụ có liên hệ với HTN planning, nhưng grammar AND/OR/GATE
và policy cụ thể ở đây là thiết kế cục bộ, không được gọi là sound/complete chỉ
vì HTN cổ điển có kết quả hình thức.[15]

#### Bước E — capability discovery bằng progressive frontier

Không chọn “Top K rồi bỏ phần còn lại”. Với mỗi goal chưa giải quyết:

1. **Hard filter:** loại source không reachable, ngoài retention/time, thiếu
   permission hoặc không có bất kỳ output type/field shape cần thiết nào.
2. **Certified frontier F0:** thêm operation có approved ProofContract khớp
   relation, subject/object types và qualifier.
3. **Metadata frontier F1:** retrieve SourceCard bằng lexical + embedding; nhận
   mọi candidate vượt threshold đã calibration, không truncate ở một K cố định.
   Rank chỉ quyết định thứ tự xét, không quyết định truth hay coverage.
4. **Adjacent expansion F2:** nếu query/probe báo thiếu field/relation, mở source
   cùng partition, field alias, join key hoặc source lân cận trong catalog.
5. **Bounded semantic profiling F3:** LLM xem một batch SourceCard nhỏ cho đúng
   một unresolved goal và đề xuất mapping `retrieval_only`.
6. **Approved exhaustive F4:** chỉ chạy khi người dùng/budget policy cho phép,
   hoặc trong offline coverage audit; vẫn chia batch và ghi cost.

Frontier dừng khi answer được chứng minh, mọi candidate đủ điều kiện đã xét,
marginal progress bằng 0 qua hai vòng, cần clarification, hoặc hết budget.
`unexamined_source_ids` luôn tồn tại trong coverage manifest. Vì vậy cách này
không phụ thuộc vào một K tùy ý nhưng cũng không giả vờ bảo đảm recall tuyệt đối.

Source score chỉ là policy ordering có thể giải thích:

```text
priority = contract_match
         + required_role_coverage
         + time_and_permission_fit
         + lexical_semantic_similarity
         + observed_joinability
         - estimated_scan_cost
         - ambiguity_penalty
```

Không có trọng số nào được gọi là “khoa học” trước khi calibration. Lưu toàn bộ
feature/score để ablation. Candidate không được loại vĩnh viễn chỉ vì score thấp;
nó nằm ở frontier sau hoặc danh sách chưa xét.

#### Bước F — entity binding có kiểm soát

Mỗi biến có `CandidateSet`, không phải một string:

```text
CandidateBinding {
  value, type, supporting_fact_ids,
  relation_contract_id, directness,
  contradictions, confidence_class
}
```

Tự bind chỉ khi có đúng một candidate đáp ứng proof contract và không có
contradiction. Nếu nhiều candidate:

1. planner thử một `DISCRIMINATOR` rẻ có thể phân biệt chúng;
2. nếu vẫn nhiều và việc chọn ảnh hưởng downstream result, trả câu hỏi cho user
   kèm candidate + bằng chứng + chi phí dự kiến;
3. CLI non-interactive ghi `NEEDS_DISAMBIGUATION` và checkpoint có thể resume;
4. cấm chọn theo tên chứa `air`, edit distance, first row, số event nhiều nhất,
   hoặc “LLM thấy hợp lý” trừ khi chúng chỉ tạo hypothesis để kiểm tiếp.

#### Bước G — QueryIntent trước, SPL sau

Query được tạo theo hai lớp:

```text
QueryIntent {
  goal_id, operation_id, mode: EXPLORE | DISCRIMINATE | PROVE,
  bound_inputs, projected_roles, predicates, time_window,
  completeness_requirement, result/scan/runtime budget
}
```

- Nếu compiler registry biểu diễn được intent: compile xác định sang SPL.
- Nếu không: một call LLM riêng chỉ nhận **một goal, một/vài SourceCard đã chọn,
  binding đã chứng minh và grammar policy** để đề xuất SPL.
- Không đưa 25 source, 617 field và 65 operation vào query-generation call.
- LLM-generated SPL là candidate, không chạy trực tiếp.

Native SPL gate bắt buộc:

- read-only command allowlist và parser/AST validation;
- chỉ index/source/sourcetype/field từ manifest hiện tại;
- literal lấy từ trusted binding; escape/parameterize bởi adapter;
- explicit earliest/latest;
- cấm output/collect/delete/update/script/network side effects;
- estimate/canary trước query đắt;
- dispatch job với `max_time`, result cap, cancellation và telemetry;
- lưu SID, `scanCount`, `runDuration`, `resultCount`, dispatch state;
- timeout phía client phải gửi cancel và kiểm trạng thái backend.

`EXPLORE` có thể rộng nhưng sample nhỏ và không cấp negative/proof license.
`PROVE` phải hẹp theo binding/contract, có projection đúng role và completeness
đủ cho acceptance rule. `head 101` không bao giờ biến query thành complete.

#### Bước H — từ row đến evidence

Pipeline bắt buộc:

```text
native row
  -> immutable Observation
  -> deterministic FieldFact
  -> CandidateRelation
  -> ProofContract evaluation
  -> EvidenceItem / AnswerCandidate
```

LLM có thể đọc một batch evidence cards để giải thích relevance, gợi ý relation
mới hoặc nêu dữ liệu còn thiếu. Nó không được:

- tạo value không xuất hiện trong cited observation;
- đổi subject/object direction;
- nâng cooccurrence thành ownership/visited/encrypted;
- gọi query partial là bằng chứng absence;
- tự đặt status `SUPPORTED`/`REFUTED`.

Mọi answer value phải qua deterministic grounding: value tồn tại đúng field/raw
span đã cite; observation thuộc query/source/window; ProofContract cho phép role
đó; mandatory qualifiers đã được chứng minh.

#### Bước I — ProofContract là authority

Proof contract tổng quát theo relation semantics, không theo case:

```text
ProofContract {
  contract_id, version, status: DRAFT | APPROVED | RETIRED,
  semantic_relation,
  subject_type, object_type,
  provider/source profile constraints,
  subject/object/native field roles and direction,
  required predicates and temporal/correlation rules,
  allowed evidence modes,
  positive_license, negative_license,
  completeness requirements,
  parser/extractor versions,
  provenance references,
  author, independent reviewer,
  positive/negative/role-swap/drift fixtures
}
```

Ba mức capability không được nhập làm một:

- `STRUCTURALLY_VALID`: source/field/type tồn tại;
- `RETRIEVAL_CAPABLE`: query/probe tìm được candidate liên quan;
- `PROOF_CAPABLE`: approved contract và conformance tests cho phép chứng minh.

Cooccurrence mặc định chỉ `RETRIEVAL_CAPABLE`. Một LLM proposal hoặc successful
probe không thể nâng lên `PROOF_CAPABLE`.

#### Bước J — controller và stopping

Controller dừng bằng state có thể kiểm tra, không hỏi LLM “đã đủ chưa?”:

- `STOP_ANSWERED`: mọi required answer slot có grounded value; mọi mandatory
  GATE trên đường được chọn đã verified; không có unresolved contradiction.
- `STOP_REFUTED`: refutation rule được chứng minh bằng proof-capable evidence.
- `STOP_NOT_FOUND_BOUNDED`: query âm complete trên đúng proof scope và contract
  cho negative license; chỉ nói không tìm thấy trong phạm vi đó.
- `STOP_NEEDS_CLARIFICATION`: nhiều binding ngang nhau hoặc request thiếu
  thông tin mà user có thể bổ sung.
- `STOP_UNSUPPORTED`: không có capability/proof contract phù hợp.
- `STOP_UNREACHABLE`: provider/permission/retention không truy cập được.
- `STOP_INCONCLUSIVE`: route đã thử nhưng proof còn thiếu.
- `STOP_BUDGET`: budget hết; ghi frontier chưa xét và checkpoint.
- `STOP_ERROR`: API/backend/validator lỗi; không tái dùng report cũ.

Không yêu cầu người dùng “phê duyệt verdict” chỉ để xuất một report read-only.
Human gate dùng cho disambiguation, mở rộng phạm vi/chi phí, native query ngoài
policy hoặc hành động có side effect. Nếu user không trả lời, run checkpoint chứ
không biến thành generic execution failure.

## 5. Thiết kế các LLM call và ngân sách

Tách call theo trách nhiệm; không có một super-prompt chứa request + graph +
toàn catalog + raw ledger.

| Call | Khi nào | Context được phép | Output | Trần mặc định ban đầu |
|---|---|---|---|---:|
| C1 `semantic_compile` | Mỗi free-text request | request, schema/vocabulary nhỏ, time policy | GoalGraph + AnswerContract | 2.500 input + 1.200 output token |
| C2 `capability_profile` | Cache miss và F0/F1 chưa đủ | một goal + batch SourceCard nhỏ + gaps | retrieval-only mappings/next exploration | 2 lần × (1.800 + 700) |
| C3 `native_query_proposal` | Typed compiler không biểu diễn được intent | một goal + selected source/op + verified bindings + SPL policy | một SPL candidate + rationale | 1.800 + 700 |
| C4 `evidence_interpret` | Chỉ khi evidence semantics mơ hồ | delta cards đã group/cite, không full ledger | candidate interpretation/missing facts | 2.500 + 800 |
| C5 `replan` | Graph bế tắc nhưng còn evidence delta đáng kể | unresolved graph + compact delta + coverage | revised goals, không verdict | 2.000 + 900 |
| C6 `narrative` | Tùy chọn, mặc định tắt | verified result/account | prose không thêm fact | 1.500 + 600 |

Default đề xuất cho pilot:

- warm path: 1–2 calls, thường 3.700–7.000 token;
- cold/novel path: 2–4 calls, thường 6.000–12.000 token;
- hard cap: 5 calls và 15.000 total token/hunt, chưa tính C6; mỗi component có
  reserve riêng để capability profiling không ăn hết budget của evidence;
- output phải là JSON schema và bị reject nếu parse/provenance sai;
- repair tối đa một lần cho C1; call khác fail thì degrade hoặc dừng, không loop.

Đây là budget khởi đầu để đo, không phải con số tối ưu đã được paper chứng minh.
AutoLink cho thấy progressive exploration có thể giảm token so với full-schema,
nhưng ExCyTIn cho thấy tăng turn có điểm bão hòa và strategy/retrieved examples
có thể tăng chi phí 1,6 lần.[1][3]

### 5.1 Kế toán chi phí

Không chỉ báo USD của LLM:

```text
C_run = C_llm + C_splunk + C_cache/control + C_analyst

C_llm = Σ(input_uncached * rate_in
        + input_cached * rate_cached
        + output * rate_out)

Splunk work = Σ(scanCount, runDuration, queue time, resultCount, cancelled state)
Human work = clarification time + review/correction minutes
```

Custom gateway/model `auto` không cho phép suy ra giá chính xác nếu không có
tariff và model route thực. Mỗi call phải ghi requested model, resolved model nếu
gateway trả, input/output/reasoning/cached token, latency, retry, error và giá
rate-card version. Nếu provider không trả token breakdown thì báo `unknown`,
không bịa estimate từ độ dài string như số liệu thật.

Chỉ số quyết định là **tổng chi phí trên một case giải quyết đúng**, đi kèm error
rate và decision coverage. Một hệ thống rẻ vì luôn dừng `INCONCLUSIVE` không đạt.

## 6. Report và khả năng quan sát

Report chính chỉ có sáu phần:

1. **Yêu cầu và câu trả lời** — answer hoặc lý do chính xác chưa thể trả lời.
2. **Graph đã phân tích** — goal, dependency, GATE/OR, provenance và trạng thái;
   hiện rõ LLM C1 đã trả gì sau validation.
3. **Quá trình** — mỗi action: tại sao chọn, input binding nào, kết quả gì, graph
   thay đổi ra sao; không in chain-of-thought bí mật.
4. **Bằng chứng** — giá trị người đọc hiểu được trước, observation IDs/citations
   sau; có link/path tới raw artifact nếu được phép.
5. **Query** — purpose, mode, source, SPL, rows/complete/scan/runtime, evidence
   sinh ra và vì sao query tiếp theo được hoặc không được chạy.
6. **Coverage và cost** — proof obligations đạt/chưa đạt, sources/frontier chưa
   xét, call/token/latency/cost và Splunk workload.

Tách `report.md` khỏi machine artifact `run_account.json`. Report không dump hàng
trăm field hay raw event; machine artifact lưu đầy đủ để audit/replay.

## 7. Kế hoạch triển khai theo phase

Mỗi phase chỉ hoàn thành khi có test/artifact. Không đánh dấu `[x]` từ việc code
compile hoặc một happy-path chạy được.

### Phase 0 — đóng băng baseline và scope

**Mục tiêu:** tránh tiếp tục sửa theo một đáp án BOTS v2.

- Lưu 20–30 request đại diện: factual lookup, multi-hop, behavior hunt, IOC/TTP,
  CVE observability, missing telemetry, ambiguous entity, multilingual.
- Tách train/dev/final holdout theo scenario/campaign; không random-split rows.
- Ghi output hiện tại: graph, queries, result, tokens, scanCount, latency.
- Chọn hai baseline tối thiểu:
  - B0: đường hiện tại;
  - B1: direct LLM-to-read-only-query với cùng budget/safety envelope.
- BOTS v2 chỉ là dev/integration fixture; final claim cần ExCyTIn/ACESEvals hoặc
  một labelled corpus độc lập bổ sung.

**Artifact:** `eval/corpus/*.jsonl`, `eval/splits.json`, baseline run accounts.  
**Gate:** cùng request/model/budget có thể replay; không có answer string, host,
username hoặc query vàng trong production code/prompt.

### Phase 1 — khóa semantic authority

**Files chính:**

- thêm `src/hunting/contracts/proof_contract.py`;
- thêm `src/hunting/registry/proof_contract_registry.py`;
- sửa `contracts/source_profile.py`, `capabilities/source_mapping_validator.py`,
  `capabilities/probe_executor.py`, `capabilities/runtime_materializer.py`;
- sửa prompt/source profiler để xóa quyền đề xuất proof-capable.

**Việc làm:**

- thêm ba status structural/retrieval/proof;
- mọi LLM mapping mặc định `retrieval_only`;
- `SourceMappingValidator` chỉ kiểm cấu trúc và retrieval eligibility;
- chỉ registry APPROVED + conformance test mới materialize proof capability;
- cache key gồm tenant/provider, principal/permission digest, scope, structural
  fingerprint, proof contract, parser/extractor, model/prompt version, freshness;
- invalidation khi quyền, schema, parser hoặc contract đổi.

**Gate bắt buộc:** mapping DNS `query -> person`, `host -> domain` dù có row vẫn
không thể thành `relation_observable`; role swap/owner-observer/cooccurrence tests
phải fail closed.

### Phase 2 — semantic compiler và graph thật

**Files chính:** `compiler/compiler.py`, `compiler/models.py`,
`contracts/semantic_graph.py`, `validator/investigation_validator.py`.

- C1 trả `AnswerContract`, atomic goals, provenance spans, AND/OR/GATE,
  assumptions và clarification triggers.
- Bỏ mọi keyword/scenario/template khỏi action selection; template chỉ còn JSON
  schema, provider compiler hoặc approved generic proof contract.
- Validator giữ nguyên entity user nêu, cấm invented proper nouns và kiểm mỗi
  downstream goal có ích cho answer slot.
- Lưu `llm_raw_proposal`, `validated_graph`, `validation_diagnostics` vào account.

**Gate:** paraphrase, tiếng Việt/Anh, tên người lạ và request không chứa các từ
`email`, `web`, `process`, `file` vẫn tạo obligation đúng theo gold annotation;
Mallory không thể đổi thành Alice; MacBook không thành hostname.

### Phase 3 — source catalog và progressive frontier

**Files chính:**

- thêm `capabilities/source_card_store.py`, `capabilities/frontier.py`,
  `capabilities/catalog_index.py`;
- sửa `census.py`, `inventory.py`, `retriever.py`, `profile_cache.py`, `engine.py`.

- tạo SourceCard incremental, compact và auditable;
- thay exhaustive per-hunt batching bằng F0–F4 frontier;
- lexical/embedding retrieval chỉ ordering; threshold/config được log;
- SourceCard gửi LLM theo token pack của đúng một goal;
- completion manifest ghi considered/rejected/unexamined + reason;
- giữ exhaustive mode chỉ cho offline oracle/audit hoặc approved escalation.

**Gate:** thêm một source có tên đánh lạc hướng nhưng fields đúng và một source
tên rất đúng nhưng fields sai; hệ thống phải xét semantics/probe, không route theo
tên. Catalog 25 source/617 field không xuất hiện trong một prompt. Rename source
không làm mất answer nếu semantics/card còn tương đương.

### Phase 4 — binding và mixed-initiative control

**Files chính:** thêm `contracts/bindings.py`, `human_loop/clarification.py`; sửa
`planner/semantic_goal_planner.py`, `planner/adaptive.py`, controller và CLI.

- CandidateSet có citations/contract/contradictions;
- planner sinh discriminator action trước khi hỏi;
- auto-bind chỉ unique proof-supported candidate;
- interactive CLI hiển thị candidate và resume token/checkpoint;
- non-interactive trả structured `NEEDS_DISAMBIGUATION`, không chọn first/best;
- bỏ mandatory confirmation cho read-only final report.

**Gate:** 1 host thì đi tiếp; 2 host ngang nhau thì discriminator hoặc hỏi; host
chứa `air` không được tự thắng; đổi tất cả tên host vẫn giữ hành vi.

### Phase 5 — typed query và native-query quarantine

**Files chính:** `contracts/query_intent.py`, `planner/semantic_query_compiler.py`,
`planner/compiler.py`, `query_safety/native_query_gate.py`, Splunk adapter.

- thêm EXPLORE/DISCRIMINATE/PROVE mode;
- deterministic compiler dùng approved mapping/pipeline trước;
- C3 chỉ nhận selected source slice, không full census;
- dùng parser/AST allowlist thay substring/regex-only check;
- adapter enforce earliest/latest/max_time/cancel và thu job statistics;
- query canary/projection test trước full bounded query;
- no-progress query signature chặn lặp cùng SPL khác whitespace.

**Gate:** query không target goal hoặc có broad `index=* | head` bị reject;
unknown field/source bị reject; timeout thực sự cancel SID; partial/truncated không
cấp negative license; LLM API fail vẫn không chạy query chưa kiểm.

### Phase 6 — evidence, verification và stopping

**Files chính:** `evidence/attribute_extractor.py`, `evidence/relation_verifier.py`,
`evidence/answer_verifier.py`, `evidence/adjudicator.py`, controller/engine.

- facts giữ native field provenance và role direction;
- contract evaluator độc lập với source profiler;
- answer verifier kiểm exact cited value + qualifier + mandatory gate;
- C4 chỉ nhận grouped delta cards; C5 chỉ khi graph bế tắc và có delta mới;
- implement stop taxonomy ở Bước J;
- no-progress hai vòng dừng/replan đúng một lần, không LLM loop.

**Gate:** DNS resolution không chứng minh person visited; process event không
chứng minh file encrypted; cooccurrence chỉ candidate; complete negative đúng
scope mới cho bounded not-found; answer đúng nhưng sai evidence bị tính fail.

### Phase 7 — report, tracing và cost

**Files chính:** `reporter/builder.py`, `reporter/renderer.py`, `controller/cost.py`,
LLM provider và Splunk adapter.

- tạo `StepTrace` thống nhất từ C1 tới stop;
- report sáu phần, link observation/raw artifact có kiểm soát;
- per-call token/model/latency/cost và per-query SID/scan/runtime/result;
- aborted run overwrite report bằng failure artifact của đúng request;
- tách machine account JSON và human report Markdown.

**Gate:** người đọc trả lời được “LLM phân tích gì, vì sao chạy query này, query
trả gì, evidence nào đổi graph, vì sao dừng” chỉ từ report; tổng cost khớp ledger.

### Phase 8 — đánh giá và quyết định giữ/bỏ

- Chạy B0, B1 và kiến trúc mới với cùng model, temperature/reasoning, budget,
  provider snapshot và question split.
- Ablation:
  - actual graph vs oracle graph;
  - dynamic mapping vs approved mapping;
  - exhaustive vs progressive frontier;
  - deterministic compiler vs quarantined C3;
  - LLM evidence interpretation on/off;
  - auto-discriminator vs immediate human clarification.
- Chạy tối thiểu ba seed/model-run cho thành phần nondeterministic; báo mean và
  dispersion theo case/campaign, không coi repeated rows là sample độc lập.
- Nếu oracle graph không cứu kết quả: lỗi nằm ở telemetry/query/proof, không tăng
  prompt. Nếu oracle mapping cứu mạnh: ưu tiên registry/discovery. Nếu B1 ngang
  chất lượng nhưng rẻ hơn: thu hẹp agent thay vì bảo vệ kiến trúc phức tạp.

## 8. Ma trận test end-to-end

| Nhóm | Tình huống | Kỳ vọng bắt buộc |
|---|---|---|
| Factual single-hop | hỏi một attribute có direct proof | 1 graph goal, query hẹp, answer có citation |
| Multi-hop | person → account/host → artifact | GATE giữ đúng; không chạy artifact query trước binding |
| OR path | person→host hoặc person→account→host | một đường verified mở gate; đường kia không bắt buộc |
| Ambiguity | hai host cùng bằng chứng | discriminator hoặc hỏi; không tự chọn |
| Missing source | relation cần source không có | `UNSUPPORTED`/coverage gap, không route source khác |
| Permission/retention | source có nhưng không query được | `UNREACHABLE`, không `NOT_FOUND` |
| Partial result | result cap/timeout | no negative license; report partial |
| Unknown native event | schema không thuộc vocabulary | observation giữ nguyên; có thể exploration, không bị drop |
| Misleading schema | tên source “email” nhưng field không chứng minh mail | không proof; tên source không route |
| Role swap | source/destination hoặc sender/recipient đảo | contract reject hoặc contradiction |
| Prompt injection in logs | row chứa instruction | không đổi graph/budget/tool policy/verdict |
| LLM compiler failure | empty/3-token/invalid JSON | một repair rồi stop/degrade rõ; không dựng graph giả |
| LLM query failure | SPL sai/unsafe | gate reject; không dispatch |
| Provider failure | Splunk down giữa run | cancel/checkpoint/error report đúng request |
| No progress | query lặp/empty không thêm fact | bounded expand/replan rồi stop; không loop |
| Cross-case generality | email, version, domain, file, TTP/CVE | cùng contract flow; không branch scenario trong code |

### 8.1 Metrics theo layer

Không dùng một F1 chung che lỗi:

| Layer | Ground truth | Metric |
|---|---|---|
| Request → graph | required/optional/forbidden goals và valid paths | goal precision/recall/F1, forbidden expansion rate, answer-slot accuracy |
| Capability retrieval | source/field/operation có liên quan do analyst gán | candidate recall, reviewed noise, sources examined, token/source, frontier coverage |
| Query | executable gold intent và denotation | execution success, denotation accuracy, scan/runtime, unsafe rejection recall |
| Binding | gold entity links | binding precision/recall/F1, incorrect auto-bind rate, clarification rate |
| Evidence | gold observation IDs/edges/roles | evidence node/edge precision/recall/F1, citation grounding |
| Answer | canonical value + aliases | exact match/value F1, supported-answer rate, false-support rate |
| Decision | eligible/answered/abstained | risk–coverage curve, decision coverage, inconclusive/error/budget rate |
| Economics | full run ledger | calls/tokens/USD, scanCount/runtime, analyst minutes, cost/correct case |

Hai safety metric phải có ceiling rất thấp và báo riêng:

- `false_support_rate`: hệ thống nói supported/answer trong khi proof sai;
- `wrong_auto_binding_rate`: hệ thống tự chọn candidate sai khi đáng lẽ phải hỏi.

## 9. Ví dụ minh họa — không phải playbook production

Với câu “Mallory's critical PowerPoint presentation on her MacBook gets
encrypted by ransomware on August 18. What is the name of this file after it
was encrypted?”, C1 hợp lý có thể tạo:

```text
AnswerSlot: encrypted_artifact.name

G1 OR-region: bind device used/owned by person(label="Mallory") on Aug 18
  Path A: person -> device
  Path B: person -> account -> device

GATE: chỉ mở G2 khi device có unique verified binding

G2: find PowerPoint artifact on bound device within window
G3: verify before/after encrypted/renamed transition for artifact
G4: extract post-transition artifact.name into AnswerSlot
```

Đây chỉ là một graph proposal. Runtime không được biết trước
`MACLORY-AIR13`, `mallory.kraeusen`, sourcetype hoặc extension ransomware.

Luồng đúng:

1. Frontier tìm source có thể liên hệ person/account/device trong census thật.
2. Query exploration bằng literal `Mallory` có thể trả nhiều host. Mỗi host là
   candidate, không phải answer.
3. Nếu một relation contract chứng minh duy nhất một device phù hợp qualifier
   MacBook thì bind. Nếu không, chạy discriminator; vẫn mơ hồ thì hỏi user.
4. Sau khi gate mở, frontier mới tìm source có file path/name, file operation,
   rename/write hoặc endpoint evidence phù hợp; không mặc định Sysmon.
5. Query proof dùng bound device + time + candidate artifact predicates.
6. Nếu chỉ thấy `.pptx` nhưng không có transition/encryption evidence, G2 có thể
   supported nhưng G3 chưa đạt; report `INCONCLUSIVE`, không bịa tên “sau mã hóa”.
7. Nếu có before/after relation đúng contract, G4 trích value đã cite và dừng
   `STOP_ANSWERED`.

Cùng runtime có thể xử lý personal email, TOR version hoặc visited domain vì chỉ
relation vocabulary, source cards, contracts và evidence thay đổi; không có
`if request contains powerpoint/email/tor`.

## 10. Definition of Done và thứ tự ưu tiên

### P0 — phải làm trước mọi tối ưu khác

- LLM không thể materialize proof-capable capability.
- GoalGraph có AnswerContract, provenance và AND/OR/GATE semantics.
- Ambiguous binding không tự chọn.
- Progressive frontier thay full-catalog prompting; coverage giữ nguồn chưa xét.
- Stop rule bám proof obligations.
- Report hiện graph/action/query result/evidence/cost.

### P1 — cần để gọi là prototype có thể đánh giá

- Native SPL quarantine với parser, runtime/scan/cancel telemetry.
- SourceCard/catalog cache có invalidation đúng quyền/schema/contract.
- Evaluation corpus, baseline, oracle ablation và layer metrics.
- Live Splunk replay cùng failure/partial/ambiguity cases.

### P2 — chỉ làm sau số đo

- provider thứ hai;
- graph database/microservices;
- online learning/tự động promote contract;
- multi-agent hoặc Best-of-N/reflection;
- autonomous side-effect/response.

MVP mới được coi là hoàn thành khi:

1. toàn bộ P0/P1 gate có execution artifact;
2. không có scenario answer/host/user/query hard-code trong production path;
3. false support và wrong auto-binding dưới ceiling đã chốt trước holdout;
4. architecture mới thắng hoặc nằm trên Pareto frontier chất lượng–chi phí so
   với B0/B1 tại cùng decision coverage;
5. failure vẫn trả account đúng request, không giữ report cũ;
6. kết quả được trình bày là evidence của workload đã test, không tuyên bố tổng
   quát cho mọi provider hay mọi cuộc tấn công.

Nếu không đạt, quyết định đúng là giữ đường đơn giản hơn hoặc thu hẹp thesis;
không tiếp tục thêm layer để che số đo xấu.

## Nguồn

[1] Wu et al., “ExCyTIn-Bench: Evaluating LLM Agents on Cyber Threat
Investigation,” ICML 2026. [Paper](https://arxiv.org/abs/2507.14201),
[implementation](https://github.com/microsoft/SecRL).

[2] Simbian AI, “Cyber Defense Benchmark: Agentic Threat Hunting Evaluation
for LLMs in SecOps,” technical report, 2026.
[arXiv](https://arxiv.org/abs/2604.19533).

[3] Wang et al., “AutoLink: Autonomous Schema Exploration and Expansion for
Scalable Schema Linking in Text-to-SQL at Scale,” AAAI 2026.
[Proceedings](https://ojs.aaai.org/index.php/AAAI/article/view/40672),
[code](https://github.com/wzy416/AutoLink).

[4] MDB-Link, “Linking Any Question to Any Database,” preprint, 2026.
[arXiv](https://arxiv.org/abs/2608.09588).

[5] Saju and Azim, “Toward Autonomous SOC Operations: End-to-End LLM
Framework for Threat Detection, Query Generation, and Resolution in Security
Operations,” PMLR 318, 2026.
[Paper](https://proceedings.mlr.press/v318/saju26a.html).

[6] Open Cybersecurity Alliance, Kestrel Threat Hunting Language,
[theory](https://kestrel.readthedocs.io/en/stable/theory.html),
[GitHub](https://github.com/opencybersecurityalliance/kestrel-lang).

[7] Gao et al., “AIQL: Enabling Efficient Attack Investigation through
Dataset-Aware Querying,” USENIX ATC 2018.
[Paper](https://www.usenix.org/conference/atc18/presentation/gao).

[8] Open Cybersecurity Schema Framework,
[schema repository](https://github.com/ocsf/ocsf-schema),
[documentation](https://github.com/ocsf/ocsf-docs).

[9] SigmaHQ, [Sigma rule repository](https://github.com/SigmaHQ/sigma),
[pySigma processing pipelines](https://sigmahq.io/docs/digging-deeper/pipelines).

[10] Hossain et al., “SLEUTH: Real-time Attack Scenario Reconstruction from
COTS Audit Data,” USENIX Security 2017.
[Paper](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-hossain.pdf).

[11] Geifman and El-Yaniv, “Selective Classification for Deep Neural
Networks,” NeurIPS 2017.
[Paper](https://proceedings.neurips.cc/paper/2017/file/4a8423d5e91fda00bb7e46540e2b0cf1-Paper.pdf).

[12] Doshi et al., “Towards Verifiably Safe Tool Use for LLM Agents,”
ICSE-NIER 2026. [DOI](https://doi.org/10.1145/3786582.3786839),
[preprint](https://arxiv.org/abs/2601.08012).

[13] Splunk, [Search endpoint and job properties](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/10.2/search-endpoints/search-endpoint-descriptions),
[tstats reference](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.1/search-commands/tstats).

[14] Microsoft, ACES/ACESEvals,
[GitHub](https://github.com/microsoft/ACESEvals).

[15] Erol, Hendler and Nau, “UMCP: A Sound and Complete Procedure for
Hierarchical Task-Network Planning,” AIPS 1994.
[Paper](https://www.cs.umd.edu/~nau/papers/erol1994umcp.pdf).

### Ghi chú về chất lượng nguồn

Nguồn conference/proceedings và tài liệu dự án chính thức được ưu tiên. Các
preprint/technical report được ghi rõ và chỉ dùng làm bằng chứng cảnh báo hoặc
gợi ý thiết kế, không làm bảo chứng duy nhất. Tài liệu vendor chứng minh khả năng
API/sản phẩm công bố, không chứng minh kiến trúc dự án có cùng hiệu quả. Mọi
ngưỡng, trọng số, budget và cache TTL trong kế hoạch là giả thuyết kỹ thuật cần
calibration trên workload thật.
