"""Data model of the public intelligence collected for one vulnerability / PoC (all of it untrusted text)."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

CVE_RE = r"CVE-\d{4}-\d{4,7}"


@dataclass
class CveInfo:
    cve_id: str
    description: str = ""
    published: str = ""
    cvss_score: float | None = None
    cvss_severity: str = ""
    cvss_vector: str = ""
    cwes: list[str] = field(default_factory=list)
    affected: list[str] = field(default_factory=list)  # "vendor:product versions" summaries from CPE
    references: list[dict[str, Any]] = field(default_factory=list)  # {"url", "tags"}
    kev: bool = False  # CISA Known Exploited Vulnerabilities (NVD carries the flag)
    kev_added: str = ""
    kev_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PocFile:
    path: str
    size: int
    text: str  # truncated, control characters removed; never executed
    kind: str = "code"  # readme | nuclei | code | doc

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "size": self.size, "kind": self.kind, "chars_read": len(self.text)}


@dataclass
class PocRepo:
    full_name: str
    url: str
    stars: int
    description: str = ""
    language: str = ""
    pushed_at: str = ""
    default_branch: str = "main"
    archived: bool = False
    fork: bool = False
    topics: list[str] = field(default_factory=list)
    below_threshold: bool = False
    files: list[PocFile] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = {k: v for k, v in asdict(self).items() if k != "files"}
        data["files"] = [f.to_dict() for f in self.files]
        return data


@dataclass
class Indicator:
    kind: str  # http_path | uri_pattern | user_agent | command | file_name | oast_domain | url_scheme
    value: str
    count: int = 1
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IntelBundle:
    query: str
    cves: list[CveInfo] = field(default_factory=list)
    repos: list[PocRepo] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    requests_made: int = 0
    cache_hits: int = 0

    @property
    def primary_cve(self) -> CveInfo | None:
        return self.cves[0] if self.cves else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "cves": [c.to_dict() for c in self.cves],
            "repos": [r.to_dict() for r in self.repos],
            "indicators": [i.to_dict() for i in self.indicators],
            "warnings": list(self.warnings),
            "requests_made": self.requests_made,
            "cache_hits": self.cache_hits,
        }
