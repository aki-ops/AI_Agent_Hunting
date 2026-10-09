"""Static safety checks for the searches that leave this project.

The searches are written by an LLM that has read internet text, and they will be run by another team on a production
Splunk. So the rule is "reject unless provably boring": read-only commands from a short allow-list, no subsearches,
no macros, exactly one index placeholder, time bounds and a row cap that this code adds itself.
"""
from __future__ import annotations

import re

from hunting.plan.catalog import PLACEHOLDERS

MAX_LEN = 1500
MAX_SEGMENTS = 10

ALLOWED_COMMANDS = {
    "search", "where", "eval", "stats", "eventstats", "streamstats", "table", "fields", "rex", "regex", "sort",
    "dedup", "top", "rare", "head", "tail", "rename", "bin", "timechart", "chart", "fillnull", "spath",
    "mvexpand", "makemv", "strcat", "reverse",
}
_INDEX_TERM = re.compile(r"(?i)\bindex\s*=\s*(\{\{INDEX_[A-Z]+\}\})")
_ANY_INDEX = re.compile(r"(?i)\bindex\s*(?:=|::|!=)")
_TIME_TERM = re.compile(r"(?i)(?<![\w\"])(?:earliest|latest|_index_earliest|_index_latest)\s*=\s*[^\s|]+")
_LITERAL_OK = re.compile(r"^[A-Za-z0-9_.\-:@/\\ %~+=,*]{1,150}$")


def _scan(text: str) -> tuple[list[str], list[str]]:
    """Split on top-level pipes. Quote-aware. Returns (segments, errors)."""
    segments: list[str] = []
    errors: list[str] = []
    buf: list[str] = []
    in_quote = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(text):
                buf.append(text[i + 1])
                i += 1
            elif ch == '"':
                in_quote = False
        else:
            if ch == '"':
                in_quote = True
                buf.append(ch)
            elif ch == "|":
                segments.append("".join(buf).strip())
                buf = []
            else:
                if ch in "[]":
                    errors.append("subsearches / square brackets outside quotes are not allowed")
                elif ch == "`":
                    errors.append("macros (backticks) are not allowed: they hide arbitrary internal logic")
                elif ch == "$":
                    errors.append("$token$ substitution is not allowed")
                elif ord(ch) < 32 and ch not in "\t":
                    errors.append("control character in the search")
                buf.append(ch)
        i += 1
    if in_quote:
        errors.append("unbalanced double quote")
    segments.append("".join(buf).strip())
    return segments, list(dict.fromkeys(errors))


_SUBSTRING_FIELDS = ("uri_query", "uri_path", "url", "http_user_agent", "http_referrer", "process", "_raw")
_FRAGMENT = re.compile(
    r'(?P<head>(?<![A-Za-z_])(?:' + "|".join(_SUBSTRING_FIELDS) + r')\s*=\s*)"(?P<val>[^"*]+)"'
)


def widen_fragments(body: str) -> tuple[str, list[str]]:
    """In Splunk ``field="x"`` is an EXACT match. A payload fragment (``${jndi:ldap://``, ``http://``) compared that way
    never matches a real value, so a plan would silently detect nothing. Wrap such fragments in wildcards."""
    notes: list[str] = []

    def fix(match: re.Match[str]) -> str:
        value = match.group("val")
        if "${" in value or "://" in value or value.endswith((":", "/", "=", "-")):
            notes.append(f"substring match: {match.group('head').strip()} \"*{value}*\" (an exact match would never see a payload fragment)")
            return f'{match.group("head")}"*{value}*"'
        return match.group(0)

    return _FRAGMENT.sub(fix, body), notes


def check_spl(spl: str) -> tuple[str | None, list[str], list[str]]:
    """Validate and normalise one detection search.

    Returns ``(normalised_spl_or_None, errors, notes)``. ``None`` whenever there are errors. The normalised search is
    ``search index={{INDEX_X}} earliest={{EARLIEST}} latest={{LATEST}} <filters> | ... | head {{MAX_ROWS}}``.
    """
    errors: list[str] = []
    notes: list[str] = []
    text = re.sub(r"\s*\r?\n\s*", " ", str(spl or "")).strip()
    if not text:
        return None, ["empty search"], notes
    if len(text) > MAX_LEN:
        return None, [f"search longer than {MAX_LEN} characters"], notes
    segments, scan_errors = _scan(text)
    errors += scan_errors
    if len(segments) > MAX_SEGMENTS:
        errors.append(f"more than {MAX_SEGMENTS} pipeline stages")
    first = segments[0] if segments else ""
    if not re.match(r"(?i)search\s+", first):
        errors.append("must start with 'search index={{INDEX_*}} ...'")
        return None, errors, notes
    body = re.sub(r"(?i)^search\s+", "", first)
    indexes = _INDEX_TERM.findall(body)
    if len(indexes) != 1 or indexes[0] not in PLACEHOLDERS:
        errors.append(f"exactly one index={{{{INDEX_*}}}} placeholder from {sorted(PLACEHOLDERS)} is required")
    elif len(_ANY_INDEX.findall(body)) != 1:
        errors.append("only the index placeholder may appear as an index term (no literal index names, no wildcards)")
    stripped = _TIME_TERM.sub("", body)
    if stripped != body:
        notes.append("time bounds removed from the search: they are injected from the plan limits")
        body = stripped
    body, fragment_notes = widen_fragments(body)
    notes += fragment_notes
    filters = _INDEX_TERM.sub("", body).strip()
    if not filters or filters == "*":
        errors.append("the search has no filter besides the index: it would read the whole index")
    for segment in segments[1:]:
        match = re.match(r"([A-Za-z_]+)", segment)
        command = match.group(1).lower() if match else ""
        if command not in ALLOWED_COMMANDS:
            errors.append(f"command '{command or segment[:20]}' is not in the allow-list")
    if errors:
        return None, list(dict.fromkeys(errors)), notes
    rebuilt_first = "search " + _INDEX_TERM.sub(lambda m: f"index={m.group(1)} earliest={{{{EARLIEST}}}} latest={{{{LATEST}}}}", body, count=1)
    rest = segments[1:]
    if not rest or not re.match(r"(?i)head\b", rest[-1]):
        rest.append("head {{MAX_ROWS}}")
    return " | ".join([re.sub(r"\s+", " ", rebuilt_first).strip(), *rest]), [], notes


_PARENT_FILTER = re.compile(
    r"(?i)(?<![A-Za-z_])parent_process(?:_name|_path|_exec)?\s*(?:=|\s+IN\b)|\b(?:match|like)\s*\(\s*parent_process\w*"
)
_FILE_FILTER = re.compile(r"(?i)(?<![A-Za-z_])(?:file_name|file_path|registry_\w+)\s*(?:=|\s+IN\b)")
PARENT_HINT = (
    'filter parent_process_name (or parent_process) to the process family of the vulnerable service, for example '
    'parent_process_name IN ("java","java.exe") for a Java application server, "w3wp.exe" for IIS, "httpd", "nginx", '
    '"php-fpm" or "php" for web servers; administrators also run whoami and shells, so a bare child-process hit proves nothing'
)


def parent_process_problem(spl: str, data_source: str) -> str | None:
    """Post-exploitation checks on process telemetry must be tied to the service that was attacked.

    ``whoami``, a shell or ``curl`` started by an administrator looks exactly like the same command started through a
    web shell. Only the parent tells them apart, so an endpoint search that does not *filter* on the parent process
    (a mention in ``stats ... by`` or ``table`` does not count) is rejected. File and registry searches are exempt.
    """
    if data_source != "endpoint":
        return None
    segments, _ = _scan(spl)
    filtering = " | ".join(s for i, s in enumerate(segments) if i == 0 or re.match(r"(?i)(?:where|regex|search)\b", s))
    if _PARENT_FILTER.search(filtering) or _FILE_FILTER.search(filtering):
        return None
    return "an endpoint (process) search has no filter on the parent process: " + PARENT_HINT


def spl_literal(value: str) -> str | None:
    """Quote an observed value for use inside a refine query, or ``None`` if it is not boring enough to embed."""
    value = str(value or "").strip()
    if not _LITERAL_OK.match(value):
        return None
    return '"' + value.replace("\\", "\\\\") + '"'


def coverage_probe(source: str, placeholder: str) -> str:
    """Cheap existence check generated from a fixed template (never by the LLM)."""
    return (
        f"| tstats count min(_time) as first_seen max(_time) as last_seen where index={placeholder} "
        "earliest={{EARLIEST}} latest={{LATEST}} by sourcetype | head 20"
    )
