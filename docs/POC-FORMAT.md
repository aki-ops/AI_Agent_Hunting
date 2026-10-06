# Định dạng PoC (`pocs/*.json`)

Một PoC là giả thuyết đã cụ thể hoá: PEAK Prepare + danh sách predicate literal. Hunt từ chối chạy nếu
thiếu `topic`, `able.behavior`, `able.location`, `able.evidence`, `scope`, `max_duration`, `plan`,
`research_refs` (`able.actor` được để trống).

```json
{
  "poc_id": "poc-joomla-rce",
  "name": "...", "kind": "ttp | cve | ioc | behavior", "summary": "...",
  "topic": "...",
  "able": {"actor": "", "behavior": "...", "location": "...", "evidence": "..."},
  "research_refs": ["..."], "scope": "...", "max_duration": "3d", "plan": "...",
  "time_window": "2016-08-10T21:36:00Z/2016-08-10T22:00:00Z",
  "steps": [
    {"step_id": "s1", "description": "...", "target_field": "domain", "op": "EQUALS",
     "value": "imreallynotbatman.com", "source_kind": "web"}
  ],
  "fallbacks": [], "references": ["MITRE ATT&CK T1190"], "expected_chain": ["web_request"]
}
```

- `op`: `EQUALS` (khớp chính xác, kèm basename) · `CONTAINS` · `STARTS_WITH` · `ENDS_WITH` · `MATCHES` (regex) · `EXISTS`.
- `source_kind`: `process` · `dns` · `web` · `authentication` · `file` · `smb`; dùng để kiểm tra độ phủ nguồn.
- `able.location` có tác dụng thực thi: nếu chứa token giống tên máy (vd. `we1149srv`) thì **mọi bước chỉ tìm trên host đó**
  (báo cáo hiển thị điều này). Đừng ghi tên máy vào `location` nếu không muốn giới hạn; nên kiểm tra host đó thực sự ghi
  nguồn tương ứng (web proxy/stream thường ghi dưới tên máy thu log, không phải máy client).
- Literal cụ thể trong `able.behavior`/`able.evidence` (tên tệp, cờ như `-enc`, IP, chuỗi trong ngoặc kép) được AND vào mọi bước.
- `time_window`: cửa sổ mặc định; `--window` ghi đè. Cửa sổ dài hơn `max_duration` bị cắt về phần cuối.
- Muốn khuyến nghị đạt tin cậy HIGH khi escalate, PoC cần có một bước trên trường kết quả (`status`, `action`...).
