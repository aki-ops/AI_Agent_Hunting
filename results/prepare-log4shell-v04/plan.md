# Kế hoạch săn: Kế hoạch săn CVE-2021-44228

- **Plan ID:** `hp-cve-2021-44228-361ea8a4` · vòng 1
- **Tạo lúc:** 2026-10-20T08:40:38Z · model `deepseek-flash` · PEAK Assistant: không
- **plan_digest:** `a2d86471f5839574eb97efe013e552d7` · **core_digest:** `ab80eec67e447ac128e4e4453c0f4219` (core_digest không đổi dù dùng model nào; plan_digest phải được chép vào kết quả khi gửi lại)
- **Quy trình thực hiện từng bước:** xem `RUNBOOK.md`. Công cụ chỉ đề xuất; mọi cổng duyệt do người quyết định.
- **Phạm vi của bản kế hoạch này:** chỉ giai đoạn **Prepare**. Không truy cập hệ thống nội bộ, không chạy PoC; các truy vấn dưới đây do đội Execute chạy trên dữ liệu của họ.

## Giả thuyết

Giả sử PoC công khai của CVE-2021-44228 được dùng để tấn công hệ thống của chúng ta; kiểm tra xem hệ thống có dấu hiệu bị khai thác không.

## Tình báo đầu vào

- **CVE:** CVE-2021-44228 · mức CRITICAL (10.0) · **CISA KEV: đã bị khai thác ngoài thực tế**
- **Mô tả:** Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnera
- **PoC:** [fullhunt/log4j-scan](https://github.com/fullhunt/log4j-scan) · 3,428 sao
- **PoC:** [NCSC-NL/log4shell](https://github.com/NCSC-NL/log4shell) · 1,882 sao · đã lưu trữ (archived)
- **PoC:** [kozmer/log4j-shell-poc](https://github.com/kozmer/log4j-shell-poc) · 1,847 sao · đã lưu trữ (archived)
- ⚠ NCSC-NL/log4shell is archived
- ⚠ kozmer/log4j-shell-poc is archived

## Hệ thống nào có thể bị ảnh hưởng

- **Sản phẩm:** apache:log4j; siemens:6bk1602-0aa12-0tp0_firmware; siemens:6bk1602-0aa22-0tp0_firmware; siemens:6bk1602-0aa32-0tp0_firmware; siemens:6bk1602-0aa42-0tp0_firmware; siemens:6bk1602-0aa52-0tp0_firmware
- **Phiên bản:** siemens:6bk1602-0aa12-0tp0_firmware <2.7.0; siemens:6bk1602-0aa22-0tp0_firmware <2.7.0; siemens:6bk1602-0aa32-0tp0_firmware <2.7.0; siemens:6bk1602-0aa42-0tp0_firmware <2.7.0; siemens:6bk1602-0aa52-0tp0_firmware <2.7.0; apache:log4j >=2.0.1 <2.3.1; apache:log4j >=2.4.0 <2.12.2; apache:log4j >=2.13.0 <2.15.0
- **Điều kiện để khai thác được:** Hệ thống chạy sản phẩm và phiên bản bị ảnh hưởng nêu trên, và dịch vụ có thể được kẻ tấn công truy cập tới.
- **Không áp dụng nếu:** Sản phẩm không có trong hệ thống, đã vá lên phiên bản không bị ảnh hưởng, hoặc dịch vụ không thể truy cập từ nguồn tấn công.

## Các giai đoạn tấn công

### S1 — Thăm dò và quét trước khi khai thác

*Giai đoạn:* `reconnaissance` · ATT&CK: T1595 · *ý nghĩa:* ngữ cảnh (nhiễu mong đợi)

Kẻ tấn công hoặc công cụ quét tự động thử User-Agent và đường dẫn đặc trưng của PoC để biết dịch vụ có dính lỗ hổng không. Đây là nhiễu mong đợi trên dịch vụ lộ ra ngoài: một kết quả khớp chưa cho thấy hệ thống bị xâm nhập.

| Dấu vết | Giá trị | Nguồn gốc |
|---|---|---|
| user_agent | `log4j-scan (https://github.com/mazen160/log4j-scan)` | có trong PoC |
| http_path | `/ExecTemplateJDK` | có trong PoC |
| http_path | `/Exploit` | có trong PoC |
| http_path | `/poll` | có trong PoC |
| http_path | `/register` | có trong PoC |

**S1-Q1** — Yêu cầu web mang User-Agent của công cụ trong PoC (nguồn `web`, có chuỗi lấy từ PoC)

```spl
search index={{INDEX_WEB}} earliest={{EARLIEST}} latest={{LATEST}} http_user_agent="*log4j-scan (https://github.com/mazen160/log4j-scan)*" | stats count by src, dest, http_user_agent | head {{MAX_ROWS}}
```
Trường kỳ vọng: src, dest, http_user_agent, count
Hoạt động hợp lệ có thể khớp: Máy quét lỗ hổng hợp lệ của chính tổ chức hoặc của nhà cung cấp dịch vụ dùng cùng công cụ.

**S1-Q2** — Yêu cầu tới đường dẫn xuất hiện trong PoC (nguồn `web`, có chuỗi lấy từ PoC)

```spl
search index={{INDEX_WEB}} earliest={{EARLIEST}} latest={{LATEST}} (uri_path="*/ExecTemplateJDK*" OR uri_path="*/Exploit*" OR uri_path="*/poll*" OR uri_path="*/register*") | stats count by src, dest, uri_path | head {{MAX_ROWS}}
```
Trường kỳ vọng: src, dest, uri_path, count
Hoạt động hợp lệ có thể khớp: Đường dẫn lấy từ ứng dụng minh hoạ trong PoC: có thể không tồn tại ở hệ thống thật, hoặc trùng đường dẫn hợp lệ của ứng dụng khác.

**Điểm dừng:**
- khi nguồn không có dữ liệu → bổ sung telemetry — Nguồn dữ liệu không có sự kiện nào trong cửa sổ: dừng giai đoạn này; kết quả rỗng KHÔNG có nghĩa là sạch.
- khi kết quả bị cắt ở trần dòng → thu hẹp rồi chạy lại — Chạm trần 200 dòng: thu hẹp (cửa sổ, host, giá trị) rồi chạy lại, không nới rộng.
- khi lỗi/quá thời gian → dừng giai đoạn — Lỗi hoặc quá thời gian: báo cho người vận hành, không tự thử lại vô hạn.
- khi hết ngân sách → dừng toàn kế hoạch — Hết ngân sách truy vấn hoặc thời gian: dừng toàn kế hoạch và báo phần đã làm.
- khi có ≥ 1 kết quả → tiếp tục — Nhiễu mong đợi trên dịch vụ lộ ra ngoài: chỉ ghi nhận, không coi là xâm nhập.
- khi không có kết quả → tiếp tục

### S2 — Gửi payload khai thác

*Giai đoạn:* `initial_access` · ATT&CK: T1190 · *ý nghĩa:* dấu hiệu nỗ lực khai thác · chạy sau S1

Yêu cầu chứa chuỗi payload, tham số hoặc header đặc trưng của PoC. Chứng minh có nỗ lực khai thác, chưa chứng minh thành công.

| Dấu vết | Giá trị | Nguồn gốc |
|---|---|---|
| uri_pattern | `${sd:k5:-:}` | có trong PoC |
| uri_pattern | `${lower:d}` | có trong PoC |
| uri_pattern | `${lower:/}` | có trong PoC |
| uri_pattern | `${j${k8s:k5:-ND}` | có trong PoC |
| uri_pattern | `${lower:.}` | có trong PoC |
| uri_pattern | `${lower::}` | có trong PoC |

**S2-Q1** — Yêu cầu chứa chuỗi payload / tham số / header đặc trưng của PoC (nguồn `web`, có chuỗi lấy từ PoC)

```spl
search index={{INDEX_WEB}} earliest={{EARLIEST}} latest={{LATEST}} (_raw="*${sd:k5:-:}*" OR _raw="*${lower:d}*" OR _raw="*${lower:/}*" OR _raw="*${j${k8s:k5:-ND}*" OR _raw="*${lower:.}*" OR _raw="*${lower::}*") | stats count by src, dest, uri_path | head {{MAX_ROWS}}
```
Trường kỳ vọng: src, dest, uri_path, count
Hoạt động hợp lệ có thể khớp: Nhật ký truy cập web thường không ghi thân POST và hầu hết header: kết quả rỗng ở đây KHÔNG loại trừ khai thác qua các kênh đó. Công cụ quét an ninh hợp lệ của tổ chức cũng có thể gửi cùng chuỗi.

**Điểm dừng:**
- khi nguồn không có dữ liệu → bổ sung telemetry — Nguồn dữ liệu không có sự kiện nào trong cửa sổ: dừng giai đoạn này; kết quả rỗng KHÔNG có nghĩa là sạch.
- khi kết quả bị cắt ở trần dòng → thu hẹp rồi chạy lại — Chạm trần 200 dòng: thu hẹp (cửa sổ, host, giá trị) rồi chạy lại, không nới rộng.
- khi lỗi/quá thời gian → dừng giai đoạn — Lỗi hoặc quá thời gian: báo cho người vận hành, không tự thử lại vô hạn.
- khi hết ngân sách → dừng toàn kế hoạch — Hết ngân sách truy vấn hoặc thời gian: dừng toàn kế hoạch và báo phần đã làm.
- khi có ≥ 1 kết quả → tiếp tục — Có nỗ lực khớp PoC (chưa chứng minh thành công): ghi nhận, sang giai đoạn sau và pivot theo giá trị quan sát được.
- khi không có kết quả → tiếp tục — Không thấy nỗ lực khớp PoC trong cửa sổ.

### S3 — Dấu hiệu thành công và hậu khai thác

*Giai đoạn:* `execution` · ATT&CK: T1059, T1071, T1505.003 · *ý nghĩa:* dấu hiệu thành công / hậu khai thác · chạy sau S2

Dịch vụ bị khai thác kết nối ra ngoài (DNS/HTTP tới tên miền out-of-band), tạo tiến trình con bất thường hoặc có tệp thực thi mới (webshell). Mọi kết quả khớp cần người săn xem ngay.

| Dấu vết | Giá trị | Nguồn gốc |
|---|---|---|
| oast_domain | `interact.sh` | có trong PoC |
| oast_domain | `dnslog.cn` | có trong PoC |
| oast_domain | `canarytokens.org` | có trong PoC |
| file_name | `login.jsp` | có trong PoC |
| file_name | `3-SNAPSHOT-all.jar` | có trong PoC |
| file_name | `Get-Log4shellVuln.ps1` | có trong PoC |

**S3-Q1** — Truy vấn DNS tới tên miền out-of-band trong PoC (xác nhận khai thác) (nguồn `dns`, có chuỗi lấy từ PoC)

```spl
search index={{INDEX_DNS}} earliest={{EARLIEST}} latest={{LATEST}} (query="*interact.sh*" OR query="*dnslog.cn*" OR query="*canarytokens.org*") | stats count by src, query | head {{MAX_ROWS}}
```
Trường kỳ vọng: src, query, count
Hoạt động hợp lệ có thể khớp: Công cụ kiểm thử an ninh hợp lệ của tổ chức dùng cùng dịch vụ out-of-band.

**S3-Q2** — Kết nối HTTP(S) đi ra tới tên miền out-of-band trong PoC (nguồn `proxy`, có chuỗi lấy từ PoC)

```spl
search index={{INDEX_PROXY}} earliest={{EARLIEST}} latest={{LATEST}} (url="*interact.sh*" OR url="*dnslog.cn*" OR url="*canarytokens.org*") | stats count by src, dest, url | head {{MAX_ROWS}}
```
Trường kỳ vọng: src, dest, url, count
Hoạt động hợp lệ có thể khớp: Công cụ kiểm thử an ninh hợp lệ của tổ chức dùng cùng dịch vụ out-of-band.

**S3-Q3** — Truy cập tệp thực thi do PoC tạo (webshell) (nguồn `web`, có chuỗi lấy từ PoC)

```spl
search index={{INDEX_WEB}} earliest={{EARLIEST}} latest={{LATEST}} uri_path="*login.jsp*" | stats count by src, dest, uri_path, http_method | head {{MAX_ROWS}}
```
Trường kỳ vọng: src, dest, uri_path, http_method, count
Hoạt động hợp lệ có thể khớp: Tên tệp trùng một tệp hợp lệ của ứng dụng: so với nội dung tệp trên máy chủ.

**S3-Q4** — Tệp thực thi do PoC tạo xuất hiện trên máy chủ (nguồn `endpoint`, có chuỗi lấy từ PoC)

```spl
search index={{INDEX_ENDPOINT}} earliest={{EARLIEST}} latest={{LATEST}} (file_name="login.jsp" OR file_name="3-SNAPSHOT-all.jar" OR file_name="Get-Log4shellVuln.ps1") | stats count by dest, user, file_path, file_name | head {{MAX_ROWS}}
```
Trường kỳ vọng: dest, user, file_path, file_name, count
Hoạt động hợp lệ có thể khớp: Quản trị viên hoặc bản cài đặt hợp lệ tạo tệp trùng tên.

**S3-Q5** — Tiến trình con bất thường của dịch vụ bị tấn công (ứng dụng Java) (nguồn `endpoint`, có chuỗi lấy từ PoC)

```spl
search index={{INDEX_ENDPOINT}} earliest={{EARLIEST}} latest={{LATEST}} parent_process_name IN ("java","java.exe","javaw.exe","tomcat*") process_name IN ("sh","bash","dash","zsh","cmd.exe","powershell.exe","pwsh.exe","whoami","curl","wget","nc","ncat") | stats count min(_time) as first_seen max(_time) as last_seen by dest, user, parent_process_name, process_name, process | head {{MAX_ROWS}}
```
Trường kỳ vọng: dest, user, parent_process_name, process_name, process, count
Hoạt động hợp lệ có thể khớp: Quản trị viên hoặc tác vụ bảo trì mở shell từ dịch vụ; so với tiến trình cha và thời điểm. Họ tiến trình cha suy ra từ tên sản phẩm trong CVE: kiểm tra đúng tên tiến trình ở môi trường của bạn.

**Điểm dừng:**
- khi nguồn không có dữ liệu → bổ sung telemetry — Nguồn dữ liệu không có sự kiện nào trong cửa sổ: dừng giai đoạn này; kết quả rỗng KHÔNG có nghĩa là sạch.
- khi kết quả bị cắt ở trần dòng → thu hẹp rồi chạy lại — Chạm trần 200 dòng: thu hẹp (cửa sổ, host, giá trị) rồi chạy lại, không nới rộng.
- khi lỗi/quá thời gian → dừng giai đoạn — Lỗi hoặc quá thời gian: báo cho người vận hành, không tự thử lại vô hạn.
- khi hết ngân sách → dừng toàn kế hoạch — Hết ngân sách truy vấn hoặc thời gian: dừng toàn kế hoạch và báo phần đã làm.
- khi có ≥ 1 kết quả → chuyển IR — Có dấu hiệu khai thác thành công: dừng mở rộng, chuyển IR kèm bằng chứng.
- khi không có kết quả → tiếp tục — Không thấy trong dữ liệu đã quét; vẫn phải xét độ phủ nguồn.

### L1 — Payload JNDI lộ trong log ứng dụng Java  ⟵ GỢI Ý CỦA LLM (chỉ chạy nếu người duyệt chấp nhận)

*Giai đoạn:* `initial_access` · ATT&CK: T1190 · *ý nghĩa:* dấu hiệu nỗ lực khai thác

Khi kẻ tấn công gửi chuỗi ${jndi:...} vào header, tham số URL hoặc body POST, chính tầng Log4j/ứng dụng Java sẽ ghi lại nguyên văn chuỗi đó vào log ứng dụng (kể cả khi request bị WAF chặn hoặc không thành công). Đây là nguồn duy nhất nhìn thấy body POST và phần lớn header - những thứ access log của web server không ghi. Sau khi lookup thất bại, log còn chứa stack trace javax.naming (CommunicationException, NameNotFoundException) do ứng dụng cố kết nối tới máy chủ LDAP/RMI của kẻ tấn công.

| Dấu vết | Giá trị | Nguồn gốc |
|---|---|---|
| log_message | `${jndi:` | có trong PoC |
| log_message | `javax.naming` | suy luận (không thấy nguyên văn trong PoC) |
| file_name | `JndiLookup.class` | có trong PoC |

**L1-Q1** — Tìm chuỗi lookup JNDI trong log ứng dụng, nơi ghi được cả header và body POST mà access log web bỏ sót (nguồn `app`, có chuỗi lấy từ PoC)

```spl
search index={{INDEX_APP}} earliest={{EARLIEST}} latest={{LATEST}} _raw="*${jndi:*" | stats count by host, source, sourcetype | head {{MAX_ROWS}}
```
Trường kỳ vọng: host, source, sourcetype
Hoạt động hợp lệ có thể khớp: Có thể trùng với hoạt động quét lỗ hổng đã được phép, kiểm thử xâm nhập của đơn vị bảo mật, hoặc lập trình viên thử nghiệm tính năng lookup. Một số framework ghi log đã URL-encode nên cần tìm thêm biến thể %24%7Bjndi; log ứng dụng có thể bị đẩy vào index khác nhau tùy cấu hình.

**L1-Q2** — Tìm lỗi lookup JNDI/class loading chứng tỏ ứng dụng đã thực sự cố gọi ra máy chủ ngoài (nguồn `app`, có chuỗi lấy từ PoC)

```spl
search index={{INDEX_APP}} earliest={{EARLIEST}} latest={{LATEST}} (_raw="*javax.naming*" OR _raw="*JndiLookup*") | stats count by host, source, sourcetype | head {{MAX_ROWS}}
```
Trường kỳ vọng: host, source, sourcetype
Hoạt động hợp lệ có thể khớp: Ứng dụng dùng JNDI hợp lệ (LDAP/AD, nguồn dữ liệu) có thể sinh javax.naming khi máy chủ LDAP nội bộ gián đoạn; thông báo vá lỗi nhắc tới JndiLookup.class cũng khớp. Cần xem dest/host và thời điểm để loại trừ sự cố hạ tầng.

**Điểm dừng:**
- khi nguồn không có dữ liệu → bổ sung telemetry — Nguồn dữ liệu không có sự kiện nào trong cửa sổ: dừng giai đoạn này; kết quả rỗng KHÔNG có nghĩa là sạch.
- khi kết quả bị cắt ở trần dòng → thu hẹp rồi chạy lại — Chạm trần 200 dòng: thu hẹp (cửa sổ, host, giá trị) rồi chạy lại, không nới rộng.
- khi lỗi/quá thời gian → dừng giai đoạn — Lỗi hoặc quá thời gian: báo cho người vận hành, không tự thử lại vô hạn.
- khi hết ngân sách → dừng toàn kế hoạch — Hết ngân sách truy vấn hoặc thời gian: dừng toàn kế hoạch và báo phần đã làm.
- khi có ≥ 1 kết quả → tiếp tục — Có nỗ lực khớp PoC (chưa chứng minh thành công): ghi nhận, sang giai đoạn sau và pivot theo giá trị quan sát được.
- khi không có kết quả → tiếp tục — Không thấy nỗ lực khớp PoC trong cửa sổ.

### L2 — Egress tới máy chủ LDAP/RMI của kẻ tấn công và tải class từ xa  ⟵ GỢI Ý CỦA LLM (chỉ chạy nếu người duyệt chấp nhận)

*Giai đoạn:* `command_and_control` · ATT&CK: T1190, T1105, T1071 · *ý nghĩa:* dấu hiệu thành công / hậu khai thác

Sau khi payload ${jndi:ldap://...} được xử lý, tiến trình Java của dịch vụ bị lỗi mở kết nối ra ngoài tới máy chủ LDAP/RMI của kẻ tấn công (thường cổng 1389 hoặc 1099) rồi tải class độc hại (Exploit.class, jar marshalsec) qua HTTP để thực thi. Đây là bước hậu khai thác mà core plan chưa phủ: core chỉ soi DNS/proxy theo domain OAST, không soi luồng mạng ra cổng LDAP/RMI bất thường và không soi việc tải tệp .class.

| Dấu vết | Giá trị | Nguồn gốc |
|---|---|---|
| network | `dest_port 1389` | suy luận (không thấy nguyên văn trong PoC) |
| network | `dest_port 1099` | suy luận (không thấy nguyên văn trong PoC) |
| url_scheme | `ldap://` | có trong PoC |
| file_name | `Exploit.class` | suy luận (không thấy nguyên văn trong PoC) |

**L2-Q1** — Phát hiện máy chủ nội bộ mở kết nối ra ngoài tới cổng LDAP/RMI không chuẩn - dấu hiệu lookup JNDI đã được thực thi (nguồn `network`)

```spl
search index={{INDEX_NETWORK}} earliest={{EARLIEST}} latest={{LATEST}} (dest_port=1389 OR dest_port=1099) | stats count by src, dest, dest_port, transport, action | head {{MAX_ROWS}}
```
Trường kỳ vọng: src, dest, dest_port, transport, action
Hoạt động hợp lệ có thể khớp: Một số ứng dụng Java dùng RMI/JMX nội bộ trên 1099, công cụ giám sát hoặc máy chủ LDAP phòng lab dùng 1389; cần kiểm tra dest là hạ tầng nội bộ hay IP/domain lạ, và chỉ tin khi src là máy chủ chạy dịch vụ Java.

**L2-Q2** — Phát hiện việc tải tệp .class hoặc jar lạ từ Internet - bước lấy mã thực thi sau lookup thành công (nguồn `proxy`, có chuỗi lấy từ PoC)

```spl
search index={{INDEX_PROXY}} earliest={{EARLIEST}} latest={{LATEST}} (url="*.class" OR url="*marshalsec*") status=200 | stats count by src, dest, url | head {{MAX_ROWS}}
```
Trường kỳ vọng: src, dest, url, status
Hoạt động hợp lệ có thể khớp: Ứng dụng Java, Maven/Gradle, ứng dụng nhúng hoặc công cụ quản trị có thể tải .class/jar hợp lệ từ kho lưu trữ nội bộ hoặc CDN; cần đối chiếu domain đích với danh sách nguồn tin cậy và thời điểm trùng với sự kiện bất thường trước đó. Nếu lưu lượng ra ngoài không qua proxy thì tìm kiếm này không thấy gì.

**Điểm dừng:**
- khi nguồn không có dữ liệu → bổ sung telemetry — Nguồn dữ liệu không có sự kiện nào trong cửa sổ: dừng giai đoạn này; kết quả rỗng KHÔNG có nghĩa là sạch.
- khi kết quả bị cắt ở trần dòng → thu hẹp rồi chạy lại — Chạm trần 200 dòng: thu hẹp (cửa sổ, host, giá trị) rồi chạy lại, không nới rộng.
- khi lỗi/quá thời gian → dừng giai đoạn — Lỗi hoặc quá thời gian: báo cho người vận hành, không tự thử lại vô hạn.
- khi hết ngân sách → dừng toàn kế hoạch — Hết ngân sách truy vấn hoặc thời gian: dừng toàn kế hoạch và báo phần đã làm.
- khi có ≥ 1 kết quả → tiếp tục — Có nỗ lực khớp PoC (chưa chứng minh thành công): ghi nhận, sang giai đoạn sau và pivot theo giá trị quan sát được.
- khi không có kết quả → tiếp tục — Không thấy nỗ lực khớp PoC trong cửa sổ.

## Kiểm tra độ phủ nguồn (chạy trước)

Kết quả rỗng chỉ có ý nghĩa khi nguồn có dữ liệu trong cửa sổ.

**C-app** — Kiểm tra nguồn 'app' có dữ liệu trong cửa sổ (rỗng ≠ sạch)

```spl
| tstats count min(_time) as first_seen max(_time) as last_seen where index={{INDEX_APP}} earliest={{EARLIEST}} latest={{LATEST}} by sourcetype | head 20
```

**C-dns** — Kiểm tra nguồn 'dns' có dữ liệu trong cửa sổ (rỗng ≠ sạch)

```spl
| tstats count min(_time) as first_seen max(_time) as last_seen where index={{INDEX_DNS}} earliest={{EARLIEST}} latest={{LATEST}} by sourcetype | head 20
```

**C-endpoint** — Kiểm tra nguồn 'endpoint' có dữ liệu trong cửa sổ (rỗng ≠ sạch)

```spl
| tstats count min(_time) as first_seen max(_time) as last_seen where index={{INDEX_ENDPOINT}} earliest={{EARLIEST}} latest={{LATEST}} by sourcetype | head 20
```

**C-network** — Kiểm tra nguồn 'network' có dữ liệu trong cửa sổ (rỗng ≠ sạch)

```spl
| tstats count min(_time) as first_seen max(_time) as last_seen where index={{INDEX_NETWORK}} earliest={{EARLIEST}} latest={{LATEST}} by sourcetype | head 20
```

**C-proxy** — Kiểm tra nguồn 'proxy' có dữ liệu trong cửa sổ (rỗng ≠ sạch)

```spl
| tstats count min(_time) as first_seen max(_time) as last_seen where index={{INDEX_PROXY}} earliest={{EARLIEST}} latest={{LATEST}} by sourcetype | head 20
```

**C-web** — Kiểm tra nguồn 'web' có dữ liệu trong cửa sổ (rỗng ≠ sạch)

```spl
| tstats count min(_time) as first_seen max(_time) as last_seen where index={{INDEX_WEB}} earliest={{EARLIEST}} latest={{LATEST}} by sourcetype | head 20
```

## Giới hạn và điểm dừng toàn kế hoạch

- Cửa sổ: 14d gần nhất
- Tối đa 30 truy vấn · 200 dòng/truy vấn · 300s/truy vấn · 3600s tổng · 3 vòng · chỉ đọc
- Chỉ chạy truy vấn đọc (search); không ghi, không xoá, không gọi lệnh ngoài, không truy vấn con.
- Mọi truy vấn phải có chỉ mục cụ thể và cửa sổ thời gian rõ ràng; không bao giờ index=* và không bao giờ thiếu earliest/latest.
- Có sự kiện ở giai đoạn 'impact' (lõi): dừng mở rộng và báo người phụ trách IR ngay kèm bằng chứng; người quyết định có mở sự cố hay không.
- Kết quả rỗng chỉ có nghĩa là không thấy trong dữ liệu và cửa sổ đã quét; nguồn không có dữ liệu thì dừng giai đoạn và bổ sung telemetry.
- Gợi ý của LLM (origin llm) chỉ chạy nếu người duyệt chấp nhận, và không bao giờ dùng để leo thang.
- Dừng sau 3 vòng hoặc khi vòng mới không còn dấu vết mới để pivot.

## Cách xác minh kết quả

- **Chuyển IR** khi: một truy vấn của giai đoạn 'impact' trả về ít nhất một sự kiện.
- **Chấp nhận (không có bằng chứng)** khi: mọi truy vấn phát hiện đã chạy (status ok, không bị cắt), mọi truy vấn độ phủ đều có dữ liệu và không giai đoạn nào có sự kiện.
- **Chạy lại có pivot** khi: có sự kiện ở giai đoạn context/indicator hoặc kết quả bị cắt: pivot theo các giá trị quan sát được.
- **Bổ sung dữ liệu** khi: truy vấn độ phủ không có dữ liệu ở một nguồn mà kế hoạch cần.
- Gửi kết quả theo `result.schema.json`; chạy `verify` để nhận quyết định và (nếu cần) kế hoạch vòng kế tiếp.

## Đã loại bỏ / ghi chú của bộ kiểm tra

- note: bỏ user_agent 'Java/.*': giống biểu thức chính quy hoặc biến trong mã PoC, không phải giá trị thật
- note: bỏ user_agent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64': quá ngắn hoặc có ký tự không an toàn để nhúng vào truy vấn

> Kế hoạch là gợi ý hỗ trợ quyết định; người săn mối đe dọa quyết định cuối cùng.
