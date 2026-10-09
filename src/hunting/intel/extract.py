"""Deterministic extraction of observables from PoC text.

Why not leave this to the LLM alone: the LLM later proposes observables for each attack stage, and every one of
them is checked against this list (and the raw PoC text). An observable that appears nowhere in the intel is marked
``inferred`` rather than ``from_poc``, so a reader can tell grounded detail from model guesswork.
"""
from __future__ import annotations

import re
from collections import Counter

from hunting.intel.models import Indicator, IntelBundle

_FS_PREFIX = ("/etc/", "/bin/", "/usr/", "/tmp/", "/var/", "/proc/", "/dev/", "/home/", "/root/", "/opt/", "/sys/", "/lib", "/sbin/")
_HTTP_CTX = re.compile(r"(?i)\b(get|post|put|delete|path|paths|url|uri|endpoint|curl|request|requests|http|https|route|href)\b")
_PATH = re.compile(r"(?<![\w.:/\-])/[A-Za-z0-9_\-.~%@+/]{2,100}(?:\?[^\s'\"`<>)\]\\]{0,100})?")
_WINPATH = re.compile(r"\b[A-Za-z]:\\\\?[\w\\. \-]{3,100}")
_UA = re.compile(r"(?i)user-agent['\"]?\s*[:=,]\s*['\"]([^'\"\n]{3,120})['\"]")
_LOOKUP = re.compile(r"\$\{[^}\n]{3,100}\}")
_OAST = re.compile(
    r"(?i)\b[a-z0-9\-.]*\.?(?:oast\.(?:pro|live|site|online|fun|me)|interact\.sh|dnslog\.cn|ceye\.io|"
    r"burpcollaborator\.net|requestbin\.\w+|webhook\.site|pipedream\.net|canarytokens\.\w+)\b"
)
_SCHEME = re.compile(r"(?i)\b(?:ldaps?|rmi|iiop|dns|jndi)://[^\s'\"<>`)]{2,80}")
_FILE = re.compile(r"(?i)\b[\w\-]{2,40}\.(?:jsp|jspx|php|aspx|ashx|war|jar|dll|exe|ps1|sh|class)\b")
_COMMANDS = (
    "powershell -enc", "-encodedcommand", "frombase64string", "invoke-expression", "iex(", "cmd.exe /c", "cmd /c",
    "/bin/sh -c", "/bin/bash -c", "bash -i", "/dev/tcp/", "nc -e", "mkfifo", "python -c", "perl -e", "certutil -urlcache",
    "bitsadmin", "mshta", "rundll32", "regsvr32", "whoami", "wget ", "curl ", "chmod +x", "base64 -d",
)
_DOTTED = re.compile(r"""['"]([A-Za-z_]\w*(?:\.[A-Za-z_]\w*(?:\[\d+\])?){3,})(?=['"=])""")
_HEADER = re.compile(r"""['"]([A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+)['"]\s*:\s*['"]""")
_STANDARD_HEADERS = {
    "content-type", "user-agent", "accept", "accept-encoding", "accept-language", "content-length", "cache-control",
    "upgrade-insecure-requests", "x-requested-with", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest", "keep-alive",
}
_NOISE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".ico", ".woff", ".md", ".txt", ".json")


def _is_plain_path(value: str) -> bool:
    if value.startswith("//") or value.lower().startswith(_FS_PREFIX) or len(value) < 4:
        return False
    if not re.search(r"[A-Za-z]", value) or value.lower().split("?", 1)[0].endswith(_NOISE_EXT):
        return False
    return value.count("/") >= 1 and not re.fullmatch(r"/[a-z]{1,2}", value)


def extract_indicators(files: list[tuple[str, str]], *, per_kind: int = 12) -> list[Indicator]:
    """``files`` is ``[(source_name, text), ...]``. Returns the most frequent observables per kind."""
    counts: dict[tuple[str, str], Counter] = {}

    def add(kind: str, value: str, source: str) -> None:
        value = value.strip().rstrip(".,;:'\"")
        if kind == "url_scheme":
            value = value.rstrip("})")
        if 2 < len(value) <= 160:
            counts.setdefault((kind, value), Counter())[source] += 1

    for source, text in files:
        for line in text.splitlines():
            low = line.lower()
            if _HTTP_CTX.search(line):
                for m in _PATH.findall(line):
                    if _is_plain_path(m):
                        add("http_path", m, source)
            for m in _PATH.findall(line):
                if m.lower().startswith(_FS_PREFIX):
                    add("file_path", m, source)
            for m in _WINPATH.findall(line):
                add("file_path", m, source)
            for m in _DOTTED.findall(line):
                add("http_param", m, source)
            for m in _HEADER.findall(line):
                if m.lower() not in _STANDARD_HEADERS:
                    add("http_header", m, source)
            for m in _UA.findall(line):
                add("user_agent", m, source)
            for m in _LOOKUP.findall(line):
                if ":" in m:
                    add("uri_pattern", m, source)
            for m in _OAST.findall(line):
                add("oast_domain", m.lower() if isinstance(m, str) else m, source)
            for m in _SCHEME.findall(line):
                add("url_scheme", m, source)
            for m in _FILE.findall(line):
                add("file_name", m, source)
            for cmd in _COMMANDS:
                if cmd in low:
                    add("command", cmd.strip(), source)

    by_kind: dict[str, list[Indicator]] = {}
    for (kind, value), sources in counts.items():
        by_kind.setdefault(kind, []).append(
            Indicator(kind=kind, value=value, count=sum(sources.values()), sources=[s for s, _ in sources.most_common(3)])
        )
    out: list[Indicator] = []
    for kind in sorted(by_kind):
        out.extend(sorted(by_kind[kind], key=lambda i: (-i.count, i.value))[:per_kind])
    return out


def grounded(value: str, bundle: IntelBundle) -> bool:
    """True when ``value`` literally appears in the collected PoC/CVE text (case-insensitive)."""
    needle = value.strip().lower()
    if len(needle) < 3:
        return False
    for repo in bundle.repos:
        if any(needle in f.text.lower() for f in repo.files) or needle in repo.description.lower():
            return True
    for cve in bundle.cves:
        if needle in cve.description.lower():
            return True
    return any(needle in i.value.lower() or i.value.lower() in needle for i in bundle.indicators)
