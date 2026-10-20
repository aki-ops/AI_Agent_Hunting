"""The deterministic core of a hunt plan.

Everything here is computed by code from the collected public intelligence, so it is the same whichever LLM (or none)
the planner is connected to: same intel in, same stages, searches, stop conditions and limits out. That is what makes the
plan's *decision-relevant* part independent of model quality. An LLM may add suggestions next to the core
(``origin="llm"``), but it can neither change nor remove a core search, and its suggestions never drive a decision.

The core is deliberately conservative. It only searches for strings that literally appear in the PoC/CVE text, it never
emits a process search without a parent-process filter (it asks a person to supply one when the product is unknown),
and every search passes the same static checker as an LLM-written one.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from hunting.intel import IntelBundle, grounded
from hunting.plan.safety import check_spl, parent_process_problem
from hunting.plan.schema import Applicability, Observable, Query, Stage, StopCondition

MAX_LITERALS = 6
MIN_LITERAL_LEN = 4
_UNSAFE = re.compile(r'["\\`\[\]|\x00-\x1f]')
_BROWSER_UA = re.compile(r"(?i)^mozilla/\d")
_CODE_LIKE = re.compile(r"\.\*|\\[dwsb]|(?<!\$)\{[A-Za-z_][\w.]*\}|%s|%d|<[a-z_]+>")  # regex or a code placeholder, not a real value
WEB_EXEC = {"jsp", "jspx", "php", "php5", "phtml", "asp", "aspx", "ashx", "cgi"}
DROPPED_FILES = WEB_EXEC | {"war", "jar", "sh", "exe", "dll", "ps1", "bat"}
DEFAULT_CHILDREN = ("sh", "bash", "dash", "zsh", "cmd.exe", "powershell.exe", "pwsh.exe", "whoami", "curl", "wget", "nc", "ncat")

# product keyword -> label, parent process names that serve it. First matching rule wins.
FAMILIES: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("ứng dụng Java", ("log4j", "log4shell", "spring", "tomcat", "struts", "weblogic", "jboss", "wildfly", "jenkins", "confluence",
                       "jira", "solr", "activemq", "jetty", "glassfish", "elasticsearch", "xwiki", "java", "jndi"),
     ("java", "java.exe", "javaw.exe", "tomcat*")),
    ("ứng dụng PHP", ("joomla", "wordpress", "drupal", "magento", "phpmyadmin", "typo3", "prestashop", "laravel", "moodle", "php"),
     ("php", "php-fpm", "php-cgi", "php-cgi.exe", "httpd", "apache2", "nginx")),
    ("IIS / .NET", ("exchange", "sharepoint", "iis", "asp.net", "aspnet", "sitecore", "dotnet"), ("w3wp.exe", "w3wp")),
    ("Node.js", ("node.js", "nodejs", "express", "next.js"), ("node", "node.exe")),
    ("ứng dụng Python", ("django", "flask", "gunicorn", "fastapi"), ("python", "python3", "gunicorn", "uwsgi")),
    ("máy chủ web", ("nginx", "httpd", "lighttpd", "apache http"), ("httpd", "apache2", "nginx")),
)


def default_stops(significance: str, max_rows: int) -> list[StopCondition]:
    """Stop conditions are generated from this template, never by the LLM."""
    stops = [
        StopCondition(when="no_data", action="collect_data", note="Nguồn dữ liệu không có sự kiện nào trong cửa sổ: dừng giai đoạn này; kết quả rỗng KHÔNG có nghĩa là sạch."),
        StopCondition(when="truncated", action="narrow", note=f"Chạm trần {max_rows} dòng: thu hẹp (cửa sổ, host, giá trị) rồi chạy lại, không nới rộng."),
        StopCondition(when="error", action="stop_stage", note="Lỗi hoặc quá thời gian: báo cho người vận hành, không tự thử lại vô hạn."),
        StopCondition(when="budget_exceeded", action="stop_plan", note="Hết ngân sách truy vấn hoặc thời gian: dừng toàn kế hoạch và báo phần đã làm."),
    ]
    if significance == "impact":
        stops += [
            StopCondition(when="hits_ge", threshold=1, action="escalate", note="Có dấu hiệu khai thác thành công: dừng mở rộng, chuyển IR kèm bằng chứng."),
            StopCondition(when="zero_hits", action="continue", note="Không thấy trong dữ liệu đã quét; vẫn phải xét độ phủ nguồn."),
        ]
    elif significance == "indicator":
        stops += [
            StopCondition(when="hits_ge", threshold=1, action="continue", note="Có nỗ lực khớp PoC (chưa chứng minh thành công): ghi nhận, sang giai đoạn sau và pivot theo giá trị quan sát được."),
            StopCondition(when="zero_hits", action="continue", note="Không thấy nỗ lực khớp PoC trong cửa sổ."),
        ]
    else:
        stops += [
            StopCondition(when="hits_ge", threshold=1, action="continue", note="Nhiễu mong đợi trên dịch vụ lộ ra ngoài: chỉ ghi nhận, không coi là xâm nhập."),
            StopCondition(when="zero_hits", action="continue", note=""),
        ]
    return stops


def quoted_literals(spl: str) -> list[str]:
    """String literals of a search (quotes paired properly, escapes honoured), wildcards trimmed."""
    found = (m.replace('\\"', '"').strip("*") for m in re.findall(r'"((?:[^"\\]|\\.)*)"', spl))
    return [m for m in found if len(m) >= 3]


@dataclass
class CoreResult:
    stages: list[Stage] = field(default_factory=list)
    manual_todo: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    parent_label: str = ""
    parent_names: tuple[str, ...] = ()


def parent_family(bundle: IntelBundle) -> tuple[str, tuple[str, ...]]:
    """Which process family serves the affected product, from the CVE text only (not from the PoC repos)."""
    cve = bundle.primary_cve
    text = " ".join([cve.description, *cve.affected]).lower() if cve else ""
    for label, keywords, names in FAMILIES:
        if any(re.search(rf"(?<![a-z]){re.escape(k)}(?![a-z])", text) for k in keywords):
            return label, names
    return "", ()


def _values(bundle: IntelBundle, kind: str, notes: list[str]) -> list[str]:
    ranked = sorted((i for i in bundle.indicators if i.kind == kind), key=lambda i: (-i.count, i.value))
    out: list[str] = []
    for item in ranked:
        value = item.value.strip()
        if kind == "http_path":
            value = value.split("?", 1)[0]  # uri_path never contains the query string
        if _CODE_LIKE.search(value):
            notes.append(f"bỏ {kind} {value[:40]!r}: giống biểu thức chính quy hoặc biến trong mã PoC, không phải giá trị thật")
            continue
        if len(value.replace("*", "")) < MIN_LITERAL_LEN or len(value) > 100 or _UNSAFE.search(value):
            notes.append(f"bỏ {kind} {value[:40]!r}: quá ngắn hoặc có ký tự không an toàn để nhúng vào truy vấn")
            continue
        if kind == "user_agent" and _BROWSER_UA.match(value):
            notes.append(f"bỏ user_agent {value!r}: User-Agent của trình duyệt thường, quá chung để làm dấu hiệu")
            continue
        if kind == "http_path" and not value.startswith("/"):
            continue
        if value not in out:
            out.append(value)
    return out[:MAX_LITERALS]


def _any_of(field_name: str, values: list[str], *, substring: bool = True) -> str:
    terms = [f'{field_name}="*{v}*"' if substring else f'{field_name}="{v}"' for v in values]
    return terms[0] if len(terms) == 1 else "(" + " OR ".join(terms) + ")"


def _child_processes(bundle: IntelBundle) -> list[str]:
    found: list[str] = []
    for item in sorted((i for i in bundle.indicators if i.kind in ("command", "process")), key=lambda i: (-i.count, i.value)):
        tokens = item.value.strip().split()
        if not tokens:
            continue
        name = PurePosixPath(tokens[0].replace("\\", "/")).name
        if re.fullmatch(r"[A-Za-z0-9_.\-]{2,40}", name) and name not in found:
            found.append(name)
    for name in DEFAULT_CHILDREN:
        if name not in found:
            found.append(name)
    return found[:14]


def build_core(bundle: IntelBundle, max_rows: int) -> CoreResult:
    """Stages S1 (context), S2 (indicator), S3 (impact), numbered by role so ids never shift between models."""
    res = CoreResult()
    notes = res.notes
    uas = _values(bundle, "user_agent", notes)
    paths = _values(bundle, "http_path", notes)
    uri_patterns = _values(bundle, "uri_pattern", notes)
    params = _values(bundle, "http_param", notes)
    headers = _values(bundle, "http_header", notes)
    patterns = list(dict.fromkeys([*uri_patterns, *params, *headers]))[:MAX_LITERALS]
    commands = [i.value for i in sorted((i for i in bundle.indicators if i.kind in ("command", "process")), key=lambda i: (-i.count, i.value))][:4]
    oast = _values(bundle, "oast_domain", notes)
    oast = [d for d in oast if not any(d != o and d.endswith("." + o) for o in oast)]  # www.x.cn adds nothing over x.cn
    names = [n for n in _values(bundle, "file_name", notes) if n not in oast]  # interact.sh is a domain, not a dropped file
    web_files = [n for n in names if n.rsplit(".", 1)[-1].lower() in WEB_EXEC]
    dropped = [n for n in names if n.rsplit(".", 1)[-1].lower() in DROPPED_FILES]
    res.parent_label, res.parent_names = parent_family(bundle)

    def make(stage_id: str, n: int, purpose: str, source: str, spl: str, fields: list[str], benign: str) -> Query | None:
        norm, errors, _ = check_spl(spl)
        problem = parent_process_problem(norm, source) if norm else None
        if norm is None or problem:
            notes.append(f"{stage_id}-Q{n}: lõi tất định tự loại một truy vấn ({'; '.join(errors) or problem})")
            return None
        literals = quoted_literals(norm)
        return Query(query_id=f"{stage_id}-Q{n}", purpose=purpose, data_source=source, spl=norm,  # type: ignore[arg-type]
                     expected_fields=fields, benign_notes=benign, role="detect", origin="core",
                     grounded=any(grounded(x, bundle) for x in literals) if literals else None)

    def push(bucket: list[Query], sid: str, *args: object) -> None:
        query = make(sid, len(bucket) + 1, *args)  # type: ignore[arg-type]
        if query is not None:
            bucket.append(query)

    def obs(kind_values: list[tuple[str, list[str]]]) -> list[Observable]:
        return [Observable(kind=k, value=v, basis="from_poc") for k, vals in kind_values for v in vals]  # type: ignore[arg-type]

    # ---- S1: context -----------------------------------------------------------------------
    s1: list[Query] = []
    if uas:
        push(s1, "S1", "Yêu cầu web mang User-Agent của công cụ trong PoC", "web",
                       f"search index={{{{INDEX_WEB}}}} {_any_of('http_user_agent', uas)} | stats count by src, dest, http_user_agent",
                       ["src", "dest", "http_user_agent", "count"],
                       "Máy quét lỗ hổng hợp lệ của chính tổ chức hoặc của nhà cung cấp dịch vụ dùng cùng công cụ.")
    if paths:
        push(s1, "S1", "Yêu cầu tới đường dẫn xuất hiện trong PoC", "web",
                       f"search index={{{{INDEX_WEB}}}} {_any_of('uri_path', paths)} | stats count by src, dest, uri_path",
                       ["src", "dest", "uri_path", "count"],
                       "Đường dẫn lấy từ ứng dụng minh hoạ trong PoC: có thể không tồn tại ở hệ thống thật, hoặc trùng đường dẫn hợp lệ của ứng dụng khác.")
    # ---- S2: indicator ---------------------------------------------------------------------
    s2: list[Query] = []
    if patterns:
        push(s2, "S2", "Yêu cầu chứa chuỗi payload / tham số / header đặc trưng của PoC", "web",
                       f"search index={{{{INDEX_WEB}}}} {_any_of('_raw', patterns)} | stats count by src, dest, uri_path",
                       ["src", "dest", "uri_path", "count"],
                       "Nhật ký truy cập web thường không ghi thân POST và hầu hết header: kết quả rỗng ở đây KHÔNG loại trừ khai thác qua các kênh đó. "
                       "Công cụ quét an ninh hợp lệ của tổ chức cũng có thể gửi cùng chuỗi.")
    # ---- S3: impact ------------------------------------------------------------------------
    s3: list[Query] = []
    if oast:
        push(s3, "S3", "Truy vấn DNS tới tên miền out-of-band trong PoC (xác nhận khai thác)", "dns",
                       f"search index={{{{INDEX_DNS}}}} {_any_of('query', oast)} | stats count by src, query",
                       ["src", "query", "count"], "Công cụ kiểm thử an ninh hợp lệ của tổ chức dùng cùng dịch vụ out-of-band.")
        push(s3, "S3", "Kết nối HTTP(S) đi ra tới tên miền out-of-band trong PoC", "proxy",
                       f"search index={{{{INDEX_PROXY}}}} {_any_of('url', oast)} | stats count by src, dest, url",
                       ["src", "dest", "url", "count"], "Công cụ kiểm thử an ninh hợp lệ của tổ chức dùng cùng dịch vụ out-of-band.")
    if web_files:
        push(s3, "S3", "Truy cập tệp thực thi do PoC tạo (webshell)", "web",
                       f"search index={{{{INDEX_WEB}}}} {_any_of('uri_path', web_files)} | stats count by src, dest, uri_path, http_method",
                       ["src", "dest", "uri_path", "http_method", "count"], "Tên tệp trùng một tệp hợp lệ của ứng dụng: so với nội dung tệp trên máy chủ.")
    if dropped:
        push(s3, "S3", "Tệp thực thi do PoC tạo xuất hiện trên máy chủ", "endpoint",
                       f"search index={{{{INDEX_ENDPOINT}}}} {_any_of('file_name', dropped, substring=False)} | stats count by dest, user, file_path, file_name",
                       ["dest", "user", "file_path", "file_name", "count"], "Quản trị viên hoặc bản cài đặt hợp lệ tạo tệp trùng tên.")
    if res.parent_names:
        parents = ",".join(f'"{p}"' for p in res.parent_names)
        children = ",".join(f'"{c}"' for c in _child_processes(bundle))
        push(s3, "S3", f"Tiến trình con bất thường của dịch vụ bị tấn công ({res.parent_label})", "endpoint",
                       f"search index={{{{INDEX_ENDPOINT}}}} parent_process_name IN ({parents}) process_name IN ({children}) "
                       "| stats count min(_time) as first_seen max(_time) as last_seen by dest, user, parent_process_name, process_name, process",
                       ["dest", "user", "parent_process_name", "process_name", "process", "count"],
                       "Quản trị viên hoặc tác vụ bảo trì mở shell từ dịch vụ; so với tiến trình cha và thời điểm. "
                       "Họ tiến trình cha suy ra từ tên sản phẩm trong CVE: kiểm tra đúng tên tiến trình ở môi trường của bạn.")
    else:
        res.manual_todo.append(
            "Chưa suy ra được dịch vụ / tiến trình cha từ tên sản phẩm trong CVE, nên kế hoạch KHÔNG có truy vấn tiến trình trên nguồn endpoint "
            "(một truy vấn như vậy mà không lọc theo tiến trình cha sẽ khớp cả thao tác của quản trị viên). Nếu có telemetry tiến trình, người săn "
            "tự bổ sung truy vấn lọc theo parent_process_name của dịch vụ bị tấn công, rồi đưa qua bước duyệt (R0)."
        )
    if not (s1 or s2 or s3):
        res.manual_todo.append(
            "Không trích được dấu vết đủ an toàn từ văn bản PoC/CVE để dựng truy vấn tất định: kế hoạch không có truy vấn lõi. "
            "Đọc intel_digest.md và tự viết truy vấn, hoặc chọn PoC khác (--min-stars thấp hơn, --repo cụ thể)."
        )

    def stage(sid: str, name: str, phase: str, techniques: list[str], sig: str, desc: str, queries: list[Query], observed: list[Observable], dep: str | None) -> Stage:
        return Stage(stage_id=sid, name=name, phase=phase, technique_ids=techniques, significance=sig,  # type: ignore[arg-type]
                     description=desc, observables=observed, data_sources=sorted({q.data_source for q in queries}),  # type: ignore[type-var]
                     queries=queries, depends_on=[dep] if dep else [], stop_conditions=default_stops(sig, max_rows), origin="core")

    previous: str | None = None
    if s1:
        res.stages.append(stage("S1", "Thăm dò và quét trước khi khai thác", "reconnaissance", ["T1595"], "context",
                                "Kẻ tấn công hoặc công cụ quét tự động thử User-Agent và đường dẫn đặc trưng của PoC để biết dịch vụ có dính lỗ hổng không. "
                                "Đây là nhiễu mong đợi trên dịch vụ lộ ra ngoài: một kết quả khớp chưa cho thấy hệ thống bị xâm nhập.",
                                s1, obs([("user_agent", uas), ("http_path", paths)]), previous))
        previous = "S1"
    if s2:
        res.stages.append(stage("S2", "Gửi payload khai thác", "initial_access", ["T1190"], "indicator",
                                "Yêu cầu chứa chuỗi payload, tham số hoặc header đặc trưng của PoC. Chứng minh có nỗ lực khai thác, chưa chứng minh thành công.",
                                s2, obs([("uri_pattern", [p for p in uri_patterns if p in patterns]), ("http_param", [p for p in params if p in patterns]),
                                         ("http_header", [p for p in headers if p in patterns])]), previous))
        previous = "S2"
    if s3:
        res.stages.append(stage("S3", "Dấu hiệu thành công và hậu khai thác", "execution", ["T1059", "T1071", "T1505.003"], "impact",
                                "Dịch vụ bị khai thác kết nối ra ngoài (DNS/HTTP tới tên miền out-of-band), tạo tiến trình con bất thường hoặc có tệp thực thi mới "
                                "(webshell). Mọi kết quả khớp cần người săn xem ngay.",
                                s3, obs([("oast_domain", oast), ("file_name", dropped), ("command", commands if res.parent_names else [])]), previous))
    return res


def core_applicability(bundle: IntelBundle) -> Applicability:
    cve = bundle.primary_cve
    products = sorted({a.split(" ")[0] for a in cve.affected})[:6] if cve else []
    return Applicability(
        products=products,
        affected_versions=(cve.affected[:8] if cve else []),
        preconditions=["Hệ thống chạy sản phẩm và phiên bản bị ảnh hưởng nêu trên, và dịch vụ có thể được kẻ tấn công truy cập tới."],
        not_applicable_if=["Sản phẩm không có trong hệ thống, đã vá lên phiên bản không bị ảnh hưởng, hoặc dịch vụ không thể truy cập từ nguồn tấn công."],
    )
