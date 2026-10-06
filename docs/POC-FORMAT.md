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
- `time_window`: cửa sổ mặc định; `--window` ghi đè. Cửa sổ dài hơn `max_duration` bị cắt về phần cuối.
- Muốn khuyến nghị đạt tin cậy HIGH khi escalate, PoC cần có một bước trên trường kết quả (`status`, `action`...).
