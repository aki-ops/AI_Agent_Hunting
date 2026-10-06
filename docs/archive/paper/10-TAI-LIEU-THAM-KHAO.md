# Chương 10 — Tài liệu tham khảo

> Phân nhóm theo chủ đề. Mã `REF-*` khớp bảng truy vết trong `03_LITERATURE-AND-TRACEABILITY.md`. Ghi chú mức độ tin cậy ở cuối chương.

## 10.1. Khung PEAK và thực hành săn mối đe dọa

- [REF-PEAK] D. Bianco, "Introducing the PEAK Threat Hunting Framework," Splunk SURGe, 04/2023. https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html
- D. Bianco, "Hypothesis-Driven Hunting with the PEAK Framework," Splunk SURGe, 05/2023. https://www.splunk.com/en_us/blog/security/peak-hypothesis-driven-threat-hunting.html
- D. Bianco, "Baseline Hunting with the PEAK Framework," Splunk SURGe, 07/2023. https://www.splunk.com/en_us/blog/security/peak-baseline-hunting.html
- R. Fetterman, "Model-Assisted Threat Hunting (M-ATH) with the PEAK Framework," Splunk SURGe, 05/2023. https://www.splunk.com/en_us/blog/security/peak-framework-math-model-assisted-threat-hunting.html
- PEAK content repo (Splunk SURGe, nay lưu tại Cisco-Talos). https://github.com/splunk/peak
- [REF-TAHITI] FI-ISAC, "TaHiTI: Targeted Hunting integrating Threat Intelligence." https://www.nvb.nl/themas/veilig-bankieren/fi-isac/tahiti/
- [REF-USENIX-TH] Maxam và cộng sự, "An Empirical Study of Threat Hunting," USENIX Security 2024. https://www.usenix.org/conference/usenixsecurity24/presentation/maxam

## 10.2. Điều tra đa chặng và đồ thị nguồn gốc

- [REF-SLEUTH] Hossain và cộng sự, "SLEUTH: Real-time Attack Scenario Reconstruction from COTS Audit Data," USENIX Security 2017. https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-hossain.pdf
- [REF-HOLMES] Milajerdi và cộng sự, "HOLMES: Real-time APT Detection through Correlation of Suspicious Information Flows," IEEE S&P 2019. https://ieeexplore.ieee.org/document/8835390/
- [REF-OMEGALOG] Hassan và cộng sự, "OmegaLog: High-Fidelity Attack Investigation via Transparent Multi-layer Log Analysis," NDSS 2020. https://experts.illinois.edu/en/publications/omegalog-high-fidelity-attack-investigation-via-transparent-multi/
- [REF-DARPA-TC] DARPA Transparent Computing engagement data. https://github.com/darpa-i2o/Transparent-Computing

## 10.3. Truy vấn logic có kiểu và trích xuất hành vi

- [REF-AIQL] Gao và cộng sự, "AIQL: Enabling Efficient Attack Investigation from System Monitoring Data," USENIX ATC 2018. https://www.usenix.org/system/files/conference/atc18/atc18-gao.pdf
- [REF-THREATRAPTOR] Gao và cộng sự, "Enabling Efficient Cyber Threat Hunting with Cyber Threat Intelligence (ThreatRaptor)," ICDE 2021. https://github.com/peng-gao-lab/threatraptor

## 10.4. Vòng giả thuyết – bằng chứng – hành động

- [REF-ECTH] "Evidential Cyber Threat Hunting," arXiv:2104.10319. https://arxiv.org/abs/2104.10319
- [REF-ATHAFI] "ATHAFI: Agile Threat Hunting And Forensic Investigation," arXiv:2003.03663. https://arxiv.org/abs/2003.03663
- [REF-EXCYTIN] Microsoft Research, "ExCyTIn-Bench: Evaluating LLM Agents on Cyber Threat Investigation." https://www.microsoft.com/en-us/research/publication/excytin-bench-evaluating-llm-agents-on-cyber-threat-investigation/

## 10.5. Schema, năng lực và chuẩn hóa

- [REF-OCSF] Open Cybersecurity Schema Framework. https://ocsf.io/
- [REF-MITRE-DC] MITRE ATT&CK Data Components. https://attack.mitre.org/datacomponents/
- [REF-MITRE-ANALYTICS] MITRE ATT&CK Detection Strategies. https://attack.mitre.org/detectionstrategies/
- [REF-OTEL] OpenTelemetry Semantic Conventions — Events. https://opentelemetry.io/docs/specs/semconv/general/events/
- [REF-MICROSOFT] Microsoft, "Advanced hunting with Security Copilot." https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-security-copilot

## 10.6. Khớp schema bằng mô hình ngôn ngữ, có kiểm sau

- [REF-SCHEMA-LLM] "Schema Matching with Large Language Models," arXiv:2407.11852. https://arxiv.org/abs/2407.11852
- [REF-REMATCH] "ReMatch: Retrieval Enhanced Schema Matching with LLMs," arXiv:2403.01567. https://arxiv.org/abs/2403.01567
- [REF-CHESS] "CHESS: Contextual Harnessing for Efficient SQL Synthesis," arXiv:2405.16755. https://arxiv.org/abs/2405.16755
- [REF-RAT-SQL] "RAT-SQL: Relation-Aware Schema Encoding and Linking for Text-to-SQL Parsers," arXiv:1911.04942. https://arxiv.org/abs/1911.04942
- [REF-ADAPTIVE-K] "Adaptive-K" (đã xem, không chọn làm chính sách chọn nguồn), arXiv:2506.08479. https://arxiv.org/abs/2506.08479
- [REF-TOOLSHED] "ToolShed," arXiv:2410.14594. https://arxiv.org/abs/2410.14594
- [REF-MDB-LINK] "MDB-Link," arXiv:2608.09588. https://arxiv.org/abs/2608.09588

## 10.7. Dùng công cụ an toàn và lập kế hoạch theo bằng chứng

- [REF-SAFE-TOOLS] "Verifiably Safe Tool Use for LLM Agents." https://doi.org/10.1145/3786582.3786839
- [REF-RPG] "Retrieve-Plan-Generation," EMNLP 2024. https://aclanthology.org/2024.emnlp-main.270/

## 10.8. Bộ dữ liệu đánh giá

- Splunk, "Boss of the SOC (BOTS) v1 Dataset." https://github.com/splunk/botsv1_data_set

---

## Ghi chú về mức độ tin cậy nguồn

Theo `03_LITERATURE-AND-TRACEABILITY.md`: các bài bình duyệt và chuẩn chính thức nâng đỡ *nguyên tắc*; các tiền ấn phẩm (arXiv) và tài liệu nhà cung cấp/thực hành nâng đỡ *thiết kế* với trọng số yếu hơn. Một lần chạy lại trong kho chỉ chứng minh đúng hành vi đã đo của lần đó, không khái quát ra mọi môi trường.

**Cảnh báo kiểm chứng:** một vài mã số arXiv trong danh mục (ví dụ REF-ADAPTIVE-K arXiv:2506.08479, REF-MDB-LINK arXiv:2608.09588) mang năm ở tương lai so với nội dung và được giữ nguyên đúng như bảng gốc trong `03_LITERATURE-AND-TRACEABILITY.md`. Nếu dùng báo cáo này cho mục đích xuất bản chính thức, cần kiểm chứng lại các mã số và liên kết trước khi nộp.
