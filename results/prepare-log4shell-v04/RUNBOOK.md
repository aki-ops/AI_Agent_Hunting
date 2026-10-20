# Quy trình thực hiện từng bước — Kế hoạch săn CVE-2021-44228

- Plan `hp-cve-2021-44228-361ea8a4` · vòng 1 · plan_digest `a2d86471f5839574eb97efe013e552d7`
- Quy trình có người trong vòng lặp: công cụ chỉ đưa ra đề xuất; mọi mục **Quyết định của người** do người trả lời.
- Làm tuần tự, không bỏ bước, ghi lại phần **Ghi lại** trước khi sang bước sau.

## R0. Duyệt kế hoạch (người, trước khi chạy bất cứ thứ gì)

- [ ] Đọc plan.md từ đầu đến cuối, kể cả mục 'Đã loại bỏ / ghi chú của bộ kiểm tra'.
- [ ] Đối chiếu mục 'Hệ thống nào có thể bị ảnh hưởng' với tài sản thật: có sản phẩm và phiên bản này không? Nếu không thì dừng và ghi 'không áp dụng'.
- [ ] Đọc từng truy vấn lõi (nguồn gốc core): tên trường (CIM) có khớp dữ liệu của bạn không, chuỗi tìm có đúng thứ nạn nhân thật sự nhận không.
- [ ] Với từng gợi ý của LLM (L1, L2): chấp nhận hoặc bỏ, ghi lại quyết định cho từng cái.
- [ ] Ghi plan_digest ở đầu plan.md vào biên bản duyệt: kết quả trả về phải nhắc lại đúng giá trị này.

**Ghi lại:**
- tên người duyệt (approved_by)
- thời điểm duyệt (approved_at)
- plan_digest
- danh sách gợi ý LLM được chấp nhận / bỏ

**Dừng lại nếu:**
- sản phẩm hoặc phiên bản không có trong hệ thống
- không hiểu một truy vấn làm gì: không chạy thứ không hiểu

**Quyết định của người:** Có duyệt kế hoạch này để chạy không? Công cụ không tự chạy bất cứ truy vấn nào.

- [ ] Đã quyết định:  ____________  (người)  ____________  (thời điểm)

## R1. Gắn chỉ mục và cửa sổ thời gian, kiểm tra truy vấn sau khi gắn

- [ ] Chọn cửa sổ thời gian cần xem (mặc định là lookback của kế hoạch). Cửa sổ phải có đầu và cuối rõ ràng và không rộng quá 90 ngày.
- [ ] Ánh xạ mỗi nguồn dữ liệu của kế hoạch sang đúng MỘT chỉ mục thật. Không dùng '*', không dùng chỉ mục nội bộ (_internal, _audit).
- [ ] Chạy: python main.py bind --plan plan.json --map web=<chỉ mục> --map endpoint=<chỉ mục> ... [--earliest ISO --latest ISO] --out queries.bound.spl
- [ ] Nếu ở R0 bạn đã chấp nhận gợi ý của LLM, thêm --accept-llm L1,L2 (đúng các mã đã chấp nhận); mặc định chỉ gắn phần lõi.
- [ ] Lệnh bind từ chối: index=*, thiếu earliest/latest, thiếu 'head N', chỉ mục sai định dạng, placeholder chưa gắn. Nếu bị từ chối thì sửa ánh xạ, đừng sửa tay SPL.
- [ ] Mở queries.bound.spl và đọc lại từng dòng một lần nữa trước khi dán vào Splunk.

**Ghi lại:**
- ánh xạ nguồn → chỉ mục đã dùng
- cửa sổ earliest / latest đã dùng

**Dừng lại nếu:**
- bind báo lỗi
- không chắc chỉ mục nào chứa nguồn dữ liệu đó
- chỉ mục quá lớn và chưa thử trên cửa sổ ngắn

**Quyết định của người:** Chỉ mục và cửa sổ thời gian có đúng phạm vi được phép tìm không?

- [ ] Đã quyết định:  ____________  (người)  ____________  (thời điểm)

## R2. Độ phủ C-app: nguồn 'app' có dữ liệu không *(tuỳ chọn: gợi ý của LLM)*

- [ ] Chạy truy vấn C-app trước mọi truy vấn phát hiện của nguồn này.
- [ ] Kết quả rỗng ở nguồn không có dữ liệu không chứng minh điều gì: đó là lý do truy vấn này chạy trước.

**Ghi lại:**
- status
- row_count
- các sourcetype thấy được và first_seen / last_seen

**Dừng lại nếu:**
- nguồn rỗng: các giai đoạn dùng nguồn này chưa có giá trị, ghi 'cần bổ sung dữ liệu' (COLLECT_DATA)

**Quyết định của người:** Nếu nguồn thiếu dữ liệu: bổ sung telemetry hay chấp nhận giới hạn này?

- [ ] Đã quyết định:  ____________  (người)  ____________  (thời điểm)

## R3. Độ phủ C-dns: nguồn 'dns' có dữ liệu không

- [ ] Chạy truy vấn C-dns trước mọi truy vấn phát hiện của nguồn này.
- [ ] Kết quả rỗng ở nguồn không có dữ liệu không chứng minh điều gì: đó là lý do truy vấn này chạy trước.

**Ghi lại:**
- status
- row_count
- các sourcetype thấy được và first_seen / last_seen

**Dừng lại nếu:**
- nguồn rỗng: các giai đoạn dùng nguồn này chưa có giá trị, ghi 'cần bổ sung dữ liệu' (COLLECT_DATA)

**Quyết định của người:** Nếu nguồn thiếu dữ liệu: bổ sung telemetry hay chấp nhận giới hạn này?

- [ ] Đã quyết định:  ____________  (người)  ____________  (thời điểm)

## R4. Độ phủ C-endpoint: nguồn 'endpoint' có dữ liệu không

- [ ] Chạy truy vấn C-endpoint trước mọi truy vấn phát hiện của nguồn này.
- [ ] Kết quả rỗng ở nguồn không có dữ liệu không chứng minh điều gì: đó là lý do truy vấn này chạy trước.

**Ghi lại:**
- status
- row_count
- các sourcetype thấy được và first_seen / last_seen

**Dừng lại nếu:**
- nguồn rỗng: các giai đoạn dùng nguồn này chưa có giá trị, ghi 'cần bổ sung dữ liệu' (COLLECT_DATA)

**Quyết định của người:** Nếu nguồn thiếu dữ liệu: bổ sung telemetry hay chấp nhận giới hạn này?

- [ ] Đã quyết định:  ____________  (người)  ____________  (thời điểm)

## R5. Độ phủ C-network: nguồn 'network' có dữ liệu không *(tuỳ chọn: gợi ý của LLM)*

- [ ] Chạy truy vấn C-network trước mọi truy vấn phát hiện của nguồn này.
- [ ] Kết quả rỗng ở nguồn không có dữ liệu không chứng minh điều gì: đó là lý do truy vấn này chạy trước.

**Ghi lại:**
- status
- row_count
- các sourcetype thấy được và first_seen / last_seen

**Dừng lại nếu:**
- nguồn rỗng: các giai đoạn dùng nguồn này chưa có giá trị, ghi 'cần bổ sung dữ liệu' (COLLECT_DATA)

**Quyết định của người:** Nếu nguồn thiếu dữ liệu: bổ sung telemetry hay chấp nhận giới hạn này?

- [ ] Đã quyết định:  ____________  (người)  ____________  (thời điểm)

## R6. Độ phủ C-proxy: nguồn 'proxy' có dữ liệu không

- [ ] Chạy truy vấn C-proxy trước mọi truy vấn phát hiện của nguồn này.
- [ ] Kết quả rỗng ở nguồn không có dữ liệu không chứng minh điều gì: đó là lý do truy vấn này chạy trước.

**Ghi lại:**
- status
- row_count
- các sourcetype thấy được và first_seen / last_seen

**Dừng lại nếu:**
- nguồn rỗng: các giai đoạn dùng nguồn này chưa có giá trị, ghi 'cần bổ sung dữ liệu' (COLLECT_DATA)

**Quyết định của người:** Nếu nguồn thiếu dữ liệu: bổ sung telemetry hay chấp nhận giới hạn này?

- [ ] Đã quyết định:  ____________  (người)  ____________  (thời điểm)

## R7. Độ phủ C-web: nguồn 'web' có dữ liệu không

- [ ] Chạy truy vấn C-web trước mọi truy vấn phát hiện của nguồn này.
- [ ] Kết quả rỗng ở nguồn không có dữ liệu không chứng minh điều gì: đó là lý do truy vấn này chạy trước.

**Ghi lại:**
- status
- row_count
- các sourcetype thấy được và first_seen / last_seen

**Dừng lại nếu:**
- nguồn rỗng: các giai đoạn dùng nguồn này chưa có giá trị, ghi 'cần bổ sung dữ liệu' (COLLECT_DATA)

**Quyết định của người:** Nếu nguồn thiếu dữ liệu: bổ sung telemetry hay chấp nhận giới hạn này?

- [ ] Đã quyết định:  ____________  (người)  ____________  (thời điểm)

## R8. Chạy S1-Q1: Yêu cầu web mang User-Agent của công cụ trong PoC

- [ ] Mở queries.bound.spl, chạy đúng truy vấn S1-Q1 (nguồn web). Không sửa SPL: muốn sửa thì dừng và quay lại R0 để duyệt lại.
- [ ] Chạy riêng từng truy vấn, đợi xong rồi mới chạy cái kế tiếp (không chạy song song nhiều truy vấn).
- [ ] Nếu chạy quá 300 giây: huỷ job và ghi status=timeout.

**Ghi lại:**
- status (ok / error / timeout)
- row_count
- truncated (true nếu chạm trần 200 dòng)
- tối đa 25 dòng mẫu đầu, bỏ dữ liệu nhạy cảm không cần thiết (không dán toàn bộ log)

**Dừng lại nếu:**
- status là error hoặc timeout: ghi lại, không tự thử lại vô hạn
- kết quả chạm trần 200 dòng: dừng giai đoạn, thu hẹp (cửa sổ, host, giá trị) rồi duyệt lại

## R9. Chạy S1-Q2: Yêu cầu tới đường dẫn xuất hiện trong PoC

- [ ] Mở queries.bound.spl, chạy đúng truy vấn S1-Q2 (nguồn web). Không sửa SPL: muốn sửa thì dừng và quay lại R0 để duyệt lại.
- [ ] Chạy riêng từng truy vấn, đợi xong rồi mới chạy cái kế tiếp (không chạy song song nhiều truy vấn).
- [ ] Nếu chạy quá 300 giây: huỷ job và ghi status=timeout.

**Ghi lại:**
- status (ok / error / timeout)
- row_count
- truncated (true nếu chạm trần 200 dòng)
- tối đa 25 dòng mẫu đầu, bỏ dữ liệu nhạy cảm không cần thiết (không dán toàn bộ log)

**Dừng lại nếu:**
- status là error hoặc timeout: ghi lại, không tự thử lại vô hạn
- kết quả chạm trần 200 dòng: dừng giai đoạn, thu hẹp (cửa sổ, host, giá trị) rồi duyệt lại

## R10. Cổng S1: đánh giá giai đoạn 'Thăm dò và quét trước khi khai thác'

- [ ] Đối chiếu kết quả các truy vấn của giai đoạn với phần 'Điểm dừng' của giai đoạn trong plan.md.
- [ ] Ghi nhận kết luận của người chạy (có / không có dấu hiệu, lý do) trước khi sang giai đoạn kế tiếp.

**Ghi lại:**
- kết luận của giai đoạn do người chạy viết

**Dừng lại nếu:**
- một truy vấn của giai đoạn lỗi hoặc chưa chạy: kết luận về giai đoạn này chưa có giá trị, chạy lại trước khi đi tiếp

**Quyết định của người:** Giai đoạn này là nhiễu nền mong đợi. Ghi nhận, không coi là xâm nhập. Có sang giai đoạn kế tiếp không?

- [ ] Đã quyết định:  ____________  (người)  ____________  (thời điểm)

## R11. Chạy S2-Q1: Yêu cầu chứa chuỗi payload / tham số / header đặc trưng của PoC

- [ ] Mở queries.bound.spl, chạy đúng truy vấn S2-Q1 (nguồn web). Không sửa SPL: muốn sửa thì dừng và quay lại R0 để duyệt lại.
- [ ] Chạy riêng từng truy vấn, đợi xong rồi mới chạy cái kế tiếp (không chạy song song nhiều truy vấn).
- [ ] Nếu chạy quá 300 giây: huỷ job và ghi status=timeout.

**Ghi lại:**
- status (ok / error / timeout)
- row_count
- truncated (true nếu chạm trần 200 dòng)
- tối đa 25 dòng mẫu đầu, bỏ dữ liệu nhạy cảm không cần thiết (không dán toàn bộ log)

**Dừng lại nếu:**
- status là error hoặc timeout: ghi lại, không tự thử lại vô hạn
- kết quả chạm trần 200 dòng: dừng giai đoạn, thu hẹp (cửa sổ, host, giá trị) rồi duyệt lại

## R12. Cổng S2: đánh giá giai đoạn 'Gửi payload khai thác'

- [ ] Đối chiếu kết quả các truy vấn của giai đoạn với phần 'Điểm dừng' của giai đoạn trong plan.md.
- [ ] Ghi nhận kết luận của người chạy (có / không có dấu hiệu, lý do) trước khi sang giai đoạn kế tiếp.

**Ghi lại:**
- kết luận của giai đoạn do người chạy viết

**Dừng lại nếu:**
- một truy vấn của giai đoạn lỗi hoặc chưa chạy: kết luận về giai đoạn này chưa có giá trị, chạy lại trước khi đi tiếp

**Quyết định của người:** Giai đoạn này chỉ chứng minh có nỗ lực khai thác. Có ghi nhận và chạy vòng pivot (REFINE) để tìm hậu quả không?

- [ ] Đã quyết định:  ____________  (người)  ____________  (thời điểm)

## R13. Chạy S3-Q1: Truy vấn DNS tới tên miền out-of-band trong PoC (xác nhận khai thác)

- [ ] Mở queries.bound.spl, chạy đúng truy vấn S3-Q1 (nguồn dns). Không sửa SPL: muốn sửa thì dừng và quay lại R0 để duyệt lại.
- [ ] Chạy riêng từng truy vấn, đợi xong rồi mới chạy cái kế tiếp (không chạy song song nhiều truy vấn).
- [ ] Nếu chạy quá 300 giây: huỷ job và ghi status=timeout.

**Ghi lại:**
- status (ok / error / timeout)
- row_count
- truncated (true nếu chạm trần 200 dòng)
- tối đa 25 dòng mẫu đầu, bỏ dữ liệu nhạy cảm không cần thiết (không dán toàn bộ log)

**Dừng lại nếu:**
- status là error hoặc timeout: ghi lại, không tự thử lại vô hạn
- kết quả chạm trần 200 dòng: dừng giai đoạn, thu hẹp (cửa sổ, host, giá trị) rồi duyệt lại

## R14. Chạy S3-Q2: Kết nối HTTP(S) đi ra tới tên miền out-of-band trong PoC

- [ ] Mở queries.bound.spl, chạy đúng truy vấn S3-Q2 (nguồn proxy). Không sửa SPL: muốn sửa thì dừng và quay lại R0 để duyệt lại.
- [ ] Chạy riêng từng truy vấn, đợi xong rồi mới chạy cái kế tiếp (không chạy song song nhiều truy vấn).
- [ ] Nếu chạy quá 300 giây: huỷ job và ghi status=timeout.

**Ghi lại:**
- status (ok / error / timeout)
- row_count
- truncated (true nếu chạm trần 200 dòng)
- tối đa 25 dòng mẫu đầu, bỏ dữ liệu nhạy cảm không cần thiết (không dán toàn bộ log)

**Dừng lại nếu:**
- status là error hoặc timeout: ghi lại, không tự thử lại vô hạn
- kết quả chạm trần 200 dòng: dừng giai đoạn, thu hẹp (cửa sổ, host, giá trị) rồi duyệt lại

## R15. Chạy S3-Q3: Truy cập tệp thực thi do PoC tạo (webshell)

- [ ] Mở queries.bound.spl, chạy đúng truy vấn S3-Q3 (nguồn web). Không sửa SPL: muốn sửa thì dừng và quay lại R0 để duyệt lại.
- [ ] Chạy riêng từng truy vấn, đợi xong rồi mới chạy cái kế tiếp (không chạy song song nhiều truy vấn).
- [ ] Nếu chạy quá 300 giây: huỷ job và ghi status=timeout.

**Ghi lại:**
- status (ok / error / timeout)
- row_count
- truncated (true nếu chạm trần 200 dòng)
- tối đa 25 dòng mẫu đầu, bỏ dữ liệu nhạy cảm không cần thiết (không dán toàn bộ log)

**Dừng lại nếu:**
- status là error hoặc timeout: ghi lại, không tự thử lại vô hạn
- kết quả chạm trần 200 dòng: dừng giai đoạn, thu hẹp (cửa sổ, host, giá trị) rồi duyệt lại

## R16. Chạy S3-Q4: Tệp thực thi do PoC tạo xuất hiện trên máy chủ

- [ ] Mở queries.bound.spl, chạy đúng truy vấn S3-Q4 (nguồn endpoint). Không sửa SPL: muốn sửa thì dừng và quay lại R0 để duyệt lại.
- [ ] Chạy riêng từng truy vấn, đợi xong rồi mới chạy cái kế tiếp (không chạy song song nhiều truy vấn).
- [ ] Nếu chạy quá 300 giây: huỷ job và ghi status=timeout.

**Ghi lại:**
- status (ok / error / timeout)
- row_count
- truncated (true nếu chạm trần 200 dòng)
- tối đa 25 dòng mẫu đầu, bỏ dữ liệu nhạy cảm không cần thiết (không dán toàn bộ log)

**Dừng lại nếu:**
- status là error hoặc timeout: ghi lại, không tự thử lại vô hạn
- kết quả chạm trần 200 dòng: dừng giai đoạn, thu hẹp (cửa sổ, host, giá trị) rồi duyệt lại

## R17. Chạy S3-Q5: Tiến trình con bất thường của dịch vụ bị tấn công (ứng dụng Java)

- [ ] Mở queries.bound.spl, chạy đúng truy vấn S3-Q5 (nguồn endpoint). Không sửa SPL: muốn sửa thì dừng và quay lại R0 để duyệt lại.
- [ ] Chạy riêng từng truy vấn, đợi xong rồi mới chạy cái kế tiếp (không chạy song song nhiều truy vấn).
- [ ] Nếu chạy quá 300 giây: huỷ job và ghi status=timeout.

**Ghi lại:**
- status (ok / error / timeout)
- row_count
- truncated (true nếu chạm trần 200 dòng)
- tối đa 25 dòng mẫu đầu, bỏ dữ liệu nhạy cảm không cần thiết (không dán toàn bộ log)

**Dừng lại nếu:**
- status là error hoặc timeout: ghi lại, không tự thử lại vô hạn
- kết quả chạm trần 200 dòng: dừng giai đoạn, thu hẹp (cửa sổ, host, giá trị) rồi duyệt lại

## R18. Cổng S3: đánh giá giai đoạn 'Dấu hiệu thành công và hậu khai thác'

- [ ] Đối chiếu kết quả các truy vấn của giai đoạn với phần 'Điểm dừng' của giai đoạn trong plan.md.
- [ ] Ghi nhận kết luận của người chạy (có / không có dấu hiệu, lý do) trước khi sang giai đoạn kế tiếp.

**Ghi lại:**
- kết luận của giai đoạn do người chạy viết

**Dừng lại nếu:**
- bất kỳ truy vấn nào có kết quả: DỪNG mở rộng, giữ nguyên bằng chứng, báo người phụ trách IR
- một truy vấn của giai đoạn lỗi hoặc chưa chạy: kết luận về giai đoạn này chưa có giá trị, chạy lại trước khi đi tiếp

**Quyết định của người:** Giai đoạn này là dấu hiệu thành công / hậu khai thác. Nếu có kết quả: có chuyển sự cố sang IR không? (công cụ chỉ gợi ý, người quyết định)

- [ ] Đã quyết định:  ____________  (người)  ____________  (thời điểm)

## R19. Chạy L1-Q1: Tìm chuỗi lookup JNDI trong log ứng dụng, nơi ghi được cả header và body POST mà access log web bỏ sót *(tuỳ chọn: gợi ý của LLM)*

- [ ] CHỈ chạy nếu bạn đã chấp nhận gợi ý này của LLM ở bước R0; nếu không, bỏ qua bước này và ghi 'skipped'.
- [ ] Mở queries.bound.spl, chạy đúng truy vấn L1-Q1 (nguồn app). Không sửa SPL: muốn sửa thì dừng và quay lại R0 để duyệt lại.
- [ ] Chạy riêng từng truy vấn, đợi xong rồi mới chạy cái kế tiếp (không chạy song song nhiều truy vấn).
- [ ] Nếu chạy quá 300 giây: huỷ job và ghi status=timeout.

**Ghi lại:**
- status (ok / error / timeout)
- row_count
- truncated (true nếu chạm trần 200 dòng)
- tối đa 25 dòng mẫu đầu, bỏ dữ liệu nhạy cảm không cần thiết (không dán toàn bộ log)

**Dừng lại nếu:**
- status là error hoặc timeout: ghi lại, không tự thử lại vô hạn
- kết quả chạm trần 200 dòng: dừng giai đoạn, thu hẹp (cửa sổ, host, giá trị) rồi duyệt lại

## R20. Chạy L1-Q2: Tìm lỗi lookup JNDI/class loading chứng tỏ ứng dụng đã thực sự cố gọi ra máy chủ ngoài *(tuỳ chọn: gợi ý của LLM)*

- [ ] CHỈ chạy nếu bạn đã chấp nhận gợi ý này của LLM ở bước R0; nếu không, bỏ qua bước này và ghi 'skipped'.
- [ ] Mở queries.bound.spl, chạy đúng truy vấn L1-Q2 (nguồn app). Không sửa SPL: muốn sửa thì dừng và quay lại R0 để duyệt lại.
- [ ] Chạy riêng từng truy vấn, đợi xong rồi mới chạy cái kế tiếp (không chạy song song nhiều truy vấn).
- [ ] Nếu chạy quá 300 giây: huỷ job và ghi status=timeout.

**Ghi lại:**
- status (ok / error / timeout)
- row_count
- truncated (true nếu chạm trần 200 dòng)
- tối đa 25 dòng mẫu đầu, bỏ dữ liệu nhạy cảm không cần thiết (không dán toàn bộ log)

**Dừng lại nếu:**
- status là error hoặc timeout: ghi lại, không tự thử lại vô hạn
- kết quả chạm trần 200 dòng: dừng giai đoạn, thu hẹp (cửa sổ, host, giá trị) rồi duyệt lại

## R21. Cổng L1: đánh giá giai đoạn 'Payload JNDI lộ trong log ứng dụng Java' *(tuỳ chọn: gợi ý của LLM)*

- [ ] Đối chiếu kết quả các truy vấn của giai đoạn với phần 'Điểm dừng' của giai đoạn trong plan.md.
- [ ] Ghi nhận kết luận của người chạy (có / không có dấu hiệu, lý do) trước khi sang giai đoạn kế tiếp.
- [ ] Giai đoạn này là gợi ý của LLM: kết quả chỉ để tham khảo, không dùng để leo thang.

**Ghi lại:**
- kết luận của giai đoạn do người chạy viết

**Dừng lại nếu:**
- một truy vấn của giai đoạn lỗi hoặc chưa chạy: kết luận về giai đoạn này chưa có giá trị, chạy lại trước khi đi tiếp

**Quyết định của người:** Giai đoạn này chỉ chứng minh có nỗ lực khai thác. Có ghi nhận và chạy vòng pivot (REFINE) để tìm hậu quả không?

- [ ] Đã quyết định:  ____________  (người)  ____________  (thời điểm)

## R22. Chạy L2-Q1: Phát hiện máy chủ nội bộ mở kết nối ra ngoài tới cổng LDAP/RMI không chuẩn - dấu hiệu lookup JNDI đã được thực thi *(tuỳ chọn: gợi ý của LLM)*

- [ ] CHỈ chạy nếu bạn đã chấp nhận gợi ý này của LLM ở bước R0; nếu không, bỏ qua bước này và ghi 'skipped'.
- [ ] Mở queries.bound.spl, chạy đúng truy vấn L2-Q1 (nguồn network). Không sửa SPL: muốn sửa thì dừng và quay lại R0 để duyệt lại.
- [ ] Chạy riêng từng truy vấn, đợi xong rồi mới chạy cái kế tiếp (không chạy song song nhiều truy vấn).
- [ ] Nếu chạy quá 300 giây: huỷ job và ghi status=timeout.

**Ghi lại:**
- status (ok / error / timeout)
- row_count
- truncated (true nếu chạm trần 200 dòng)
- tối đa 25 dòng mẫu đầu, bỏ dữ liệu nhạy cảm không cần thiết (không dán toàn bộ log)

**Dừng lại nếu:**
- status là error hoặc timeout: ghi lại, không tự thử lại vô hạn
- kết quả chạm trần 200 dòng: dừng giai đoạn, thu hẹp (cửa sổ, host, giá trị) rồi duyệt lại

## R23. Chạy L2-Q2: Phát hiện việc tải tệp .class hoặc jar lạ từ Internet - bước lấy mã thực thi sau lookup thành công *(tuỳ chọn: gợi ý của LLM)*

- [ ] CHỈ chạy nếu bạn đã chấp nhận gợi ý này của LLM ở bước R0; nếu không, bỏ qua bước này và ghi 'skipped'.
- [ ] Mở queries.bound.spl, chạy đúng truy vấn L2-Q2 (nguồn proxy). Không sửa SPL: muốn sửa thì dừng và quay lại R0 để duyệt lại.
- [ ] Chạy riêng từng truy vấn, đợi xong rồi mới chạy cái kế tiếp (không chạy song song nhiều truy vấn).
- [ ] Nếu chạy quá 300 giây: huỷ job và ghi status=timeout.

**Ghi lại:**
- status (ok / error / timeout)
- row_count
- truncated (true nếu chạm trần 200 dòng)
- tối đa 25 dòng mẫu đầu, bỏ dữ liệu nhạy cảm không cần thiết (không dán toàn bộ log)

**Dừng lại nếu:**
- status là error hoặc timeout: ghi lại, không tự thử lại vô hạn
- kết quả chạm trần 200 dòng: dừng giai đoạn, thu hẹp (cửa sổ, host, giá trị) rồi duyệt lại

## R24. Cổng L2: đánh giá giai đoạn 'Egress tới máy chủ LDAP/RMI của kẻ tấn công và tải class từ xa' *(tuỳ chọn: gợi ý của LLM)*

- [ ] Đối chiếu kết quả các truy vấn của giai đoạn với phần 'Điểm dừng' của giai đoạn trong plan.md.
- [ ] Ghi nhận kết luận của người chạy (có / không có dấu hiệu, lý do) trước khi sang giai đoạn kế tiếp.
- [ ] Giai đoạn này là gợi ý của LLM: kết quả chỉ để tham khảo, không dùng để leo thang.

**Ghi lại:**
- kết luận của giai đoạn do người chạy viết

**Dừng lại nếu:**
- một truy vấn của giai đoạn lỗi hoặc chưa chạy: kết luận về giai đoạn này chưa có giá trị, chạy lại trước khi đi tiếp

**Quyết định của người:** Giai đoạn này là dấu hiệu thành công / hậu khai thác. Nếu có kết quả: có chuyển sự cố sang IR không? (công cụ chỉ gợi ý, người quyết định)

- [ ] Đã quyết định:  ____________  (người)  ____________  (thời điểm)

## R25. Điền kết quả và gửi để xác minh

- [ ] Điền result.template.json: plan_digest, approved_by, approved_at, executor, và kết quả từng truy vấn (đúng query_id).
- [ ] Truy vấn không chạy thì để status=skipped; không xoá khỏi danh sách và không đoán kết quả.
- [ ] Chạy: python main.py verify --plan plan.json --results results.json

**Ghi lại:**
- results.json đã điền
- verification.md

**Dừng lại nếu:**
- verify báo REJECT_RESULTS: kết quả không thuộc kế hoạch đã duyệt, kiểm tra plan_id và plan_digest

## R26. Đọc verification.md và quyết định (người)

- [ ] Đọc 'Quyết định' và 'Việc con người cần quyết định' trong verification.md; công cụ chỉ đưa gợi ý có lý do.
- [ ] Nếu quyết định là REFINE: kế hoạch vòng sau là một kế hoạch MỚI, có plan_digest mới; duyệt lại từ R0.
- [ ] Nếu ACCEPT_NO_EVIDENCE: ghi 'không thấy bằng chứng trong phạm vi đã quét', không ghi 'sạch'.

**Ghi lại:**
- quyết định cuối cùng, người quyết định, thời điểm, lý do

**Quyết định của người:** Quyết định cuối cùng (chuyển IR / dừng / chạy vòng tiếp / bổ sung dữ liệu) thuộc về người. Công cụ không thực hiện hành động nào.

- [ ] Đã quyết định:  ____________  (người)  ____________  (thời điểm)

