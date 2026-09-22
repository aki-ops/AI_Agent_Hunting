# AI Agent Hunting: Tác tử điều tra mối đe dọa bị ràng buộc bởi bằng chứng, vận hành theo khung PEAK

**Báo cáo nghiên cứu kỹ thuật**

---

## Trang thông tin

| Mục | Giá trị |
|---|---|
| Tên hệ thống | AI Agent Hunting — gói Python `hunting` v0.1.0 |
| Hợp đồng kiến trúc | v7 (`01_FINAL-ARCHITECTURE.md`) |
| Khung quy trình | PEAK — Prepare, Execute, Act + Knowledge (Splunk SURGe) |
| Phạm vi mã kiểm kê | `src/hunting`: 260 lớp, 658 hàm/phương thức |
| Bộ kiểm thử | 74 tệp unit, 1 tệp integration, 2 tệp eval |
| Kết quả kiểm thử (phiên báo cáo) | 514 passed, 13 skipped, 0 failed |
| Dữ liệu đánh giá | BOTS v1: eval DB 4.42M dòng + sample 16 sự kiện |
| Ngày lập báo cáo | 2026-09-22 |
| Đối tượng đọc | người triển khai, người phản biện kiến trúc, nhà phân tích SOC, hội đồng đánh giá |

---

## Cách đọc báo cáo này

Báo cáo được tổ chức thành **chín chương** cộng tài liệu tham khảo và phụ lục, mỗi chương là một tệp riêng trong thư mục `docs/paper/`. Cấu trúc theo khuôn một báo cáo nghiên cứu: mở đầu → cơ sở lý thuyết → thiết kế → thực nghiệm → kết quả → bàn luận → kết luận.

Nguyên tắc trung thực xuyên suốt: **mọi con số đều truy được về một tệp nguồn trong kho hoặc một lần chạy đã ghi lại; phần chưa đo được nói rõ là chưa đo.** "Nâng đỡ bởi tài liệu" không đồng nghĩa "chứng minh đúng hiện thực cụ thể".

---

## Mục lục

| Chương | Tệp | Nội dung |
|---|---|---|
| — | `00-MUC-LUC-VA-TOM-TAT.md` | Trang thông tin, mục lục, tóm tắt (tài liệu này) |
| 1 | `01-MO-DAU.md` | Mở đầu: bối cảnh, bài toán, câu hỏi nghiên cứu, đóng góp, phạm vi |
| 2 | `02-CO-SO-LY-THUYET.md` | Cơ sở lý thuyết săn mối đe dọa và các công trình liên quan |
| 3 | `03-KHUNG-PEAK.md` | Khung PEAK của Splunk và cách hệ thống hiện thực hóa |
| 4 | `04-KIEN-TRUC-HE-THONG.md` | Kiến trúc hệ thống và mô hình nhận thức năm tầng |
| 5 | `05-CONG-PEAK-PREPARE.md` | Cổng PEAK Prepare bắt buộc — đóng góp kỹ thuật mới nhất |
| 6 | `06-PHUONG-PHAP-THUC-NGHIEM.md` | Môi trường, dữ liệu BOTS v1, thiết kế kiểm thử |
| 7 | `07-KET-QUA.md` | Kết quả và phân tích tỉ lệ từng lớp test |
| 8 | `08-BAN-LUAN-VA-HAN-CHE.md` | Bàn luận, diễn giải kết quả, hạn chế trung thực |
| 9 | `09-KET-LUAN.md` | Kết luận và hướng phát triển |
| — | `10-TAI-LIEU-THAM-KHAO.md` | Tài liệu tham khảo phân nhóm theo chủ đề |
| — | `11-PHU-LUC.md` | Phụ lục: thuật ngữ, tài liệu nội bộ, trỏ tới danh mục code |

> Tài liệu một-tệp trước đây (`docs/PAPER-BAO-CAO-HE-THONG.md`) vẫn được giữ làm bản tóm lược. Bản nhiều chương này là bản chi tiết.

---

## Tóm tắt (Abstract)

**Bối cảnh.** Các tác tử điều tra an ninh dựa trên mô hình ngôn ngữ lớn (LLM) thường mắc ba lỗi cố hữu: (1) để mô hình viết thẳng truy vấn gốc rồi tự tuyên bố kết quả; (2) để một từ khóa trong câu hỏi chọn sẵn một kịch bản điều tra; (3) đọc một truy vấn trả về rỗng thành "không có tấn công". Ba lỗi này làm kết luận của tác tử không đáng tin về mặt bằng chứng.

**Mục tiêu.** Xây dựng một tác tử săn mối đe dọa mà **quyết định thuộc về logic tất định, không thuộc về mô hình ngôn ngữ**, đồng thời bám theo một quy trình săn được ngành công nhận — khung PEAK của Splunk SURGe.

**Phương pháp.** Hệ thống tách ba đồ thị có kiểu: `SemanticGoalGraph` (điều cần chứng minh), `CapabilityGraph` (nguồn nào quan sát được điều đó), `EvidenceGraph` (điều gì đã quan sát và kiểm chứng). Mô hình ngôn ngữ chỉ *đề xuất* đồ thị mục tiêu và ánh xạ nguồn–trường; census, probe, adapter, sổ cái append-only, bộ kiểm chứng quan hệ và bộ điều khiển tất định mới tạo ra sự thật. Hệ thống hiện thực hóa bốn cửa của PEAK (Prepare, Execute/Refine, Act, và M-ATH qua model pretrained ngoài) và, trong phiên bản này, **ép cổng PEAK Prepare thành bắt buộc trên mọi đường săn**. Đánh giá thực hiện trên bộ dữ liệu công khai Boss of the SOC v1 (BOTS v1).

**Kết quả.** (i) Bộ kiểm thử phần mềm: 514 test đạt, 13 bỏ qua, 0 thất bại. (ii) Độ đặc hiệu: bốn PoC dựng sẵn chạy trên 4.38 triệu dòng telemetry lành tính cho **0 dương tính giả** (trước khi sửa hai lỗi là 0.000023). (iii) Độ nhạy trên tấn công thật: PoC Joomla RCE trên ~19.7 nghìn dòng web thật cho **MATCHED, 199 quan sát, 2/2 bước**, và LLM judge chấm TRUE_POSITIVE (0.85–0.87).

**Kết luận.** Hệ thống phát hiện được tấn công thật mà không báo bừa trên nhiễu lành tính, đồng thời giữ được ranh giới nhận thức chặt: mô hình đề xuất, logic tất định quyết định. Hạn chế chính còn lại: recall mới đo được một chặng tấn công, và F1 tổng quát chưa đo được do thiếu nhãn đầy đủ.

**Từ khóa.** săn mối đe dọa, PEAK, điều tra dựa trên bằng chứng, đồ thị năng lực, tác tử LLM có ràng buộc, BOTS v1, MITRE ATT&CK.
