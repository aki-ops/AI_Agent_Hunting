"""Readers for the public sources: NVD (CVE facts + CISA KEV flag) and GitHub (PoC repositories).

Nothing here clones, installs or runs a PoC. Repository files are fetched as text through
``raw.githubusercontent.com`` with size caps, and only to extract observables.
"""
from __future__ import annotations

import re
from typing import Any

from hunting.intel.http import Fetcher
from hunting.intel.models import CveInfo, PocFile, PocRepo

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"

_TEXT_EXT = {
    ".py", ".go", ".sh", ".rb", ".js", ".ts", ".ps1", ".yaml", ".yml", ".nse", ".java", ".php", ".pl",
    ".c", ".cpp", ".rs", ".txt", ".md", ".json", ".http", ".rules", ".conf", ".xml", ".html",
}
_SKIP_DIRS = {"node_modules", "vendor", ".git", ".idea", ".vscode", ".github", "dist", "build", "third_party", "docs/images", "images", "img", "assets"}
_SKIP_NAMES = ("license", "licence", "copying", "changelog", "package-lock.json", "yarn.lock", "poetry.lock", "requirements.txt", ".gitignore", "go.sum")
_NAME_HINTS = ("exploit", "poc", "scan", "check", "cve", "attack", "payload", "detect", "rce", "main")


def nvd_lookup(fetcher: Fetcher, cve_id: str) -> CveInfo | None:
    data = fetcher.json(NVD_URL, {"cveId": cve_id.upper()})
    items = (data or {}).get("vulnerabilities") or []
    if not items:
        return None
    cve = items[0].get("cve", {})
    description = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    info = CveInfo(cve_id=cve.get("id", cve_id.upper()), description=description, published=cve.get("published", ""))
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            cvss = metrics[key][0].get("cvssData", {})
            info.cvss_score = cvss.get("baseScore")
            info.cvss_severity = str(cvss.get("baseSeverity") or metrics[key][0].get("baseSeverity") or "")
            info.cvss_vector = str(cvss.get("vectorString", ""))
            break
    info.cwes = sorted({d.get("value", "") for w in cve.get("weaknesses", []) for d in w.get("description", []) if d.get("value", "").startswith("CWE-")})
    affected: list[str] = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                parts = str(match.get("criteria", "")).split(":")
                if len(parts) < 6:
                    continue
                rng = " ".join(
                    f"{label}{match[key]}" for key, label in (
                        ("versionStartIncluding", ">="), ("versionStartExcluding", ">"),
                        ("versionEndIncluding", "<="), ("versionEndExcluding", "<"),
                    ) if match.get(key)
                ) or (parts[5] if parts[5] not in ("*", "-") else "all versions")
                affected.append(f"{parts[3]}:{parts[4]} {rng}")
    info.affected = list(dict.fromkeys(affected))[:15]
    info.references = [
        {"url": r.get("url", ""), "tags": r.get("tags", [])} for r in cve.get("references", [])[:12]
    ]
    if cve.get("cisaExploitAdd"):
        info.kev, info.kev_added, info.kev_name = True, str(cve["cisaExploitAdd"]), str(cve.get("cisaVulnerabilityName", ""))
    return info


def _repo_from_api(item: dict[str, Any], min_stars: int) -> PocRepo:
    return PocRepo(
        full_name=item["full_name"],
        url=item.get("html_url", f"https://github.com/{item['full_name']}"),
        stars=int(item.get("stargazers_count", 0)),
        description=str(item.get("description") or ""),
        language=str(item.get("language") or ""),
        pushed_at=str(item.get("pushed_at") or ""),
        default_branch=str(item.get("default_branch") or "main"),
        archived=bool(item.get("archived")),
        fork=bool(item.get("fork")),
        topics=list(item.get("topics") or []),
        below_threshold=int(item.get("stargazers_count", 0)) < min_stars,
    )


def github_search(fetcher: Fetcher, query: str, *, min_stars: int = 50, limit: int = 3) -> list[PocRepo]:
    """Most-starred repositories matching ``query``; forks are dropped. If nothing reaches ``min_stars`` the best ones
    are still returned, flagged ``below_threshold``, so the caller can say so instead of silently using weak input."""
    data = fetcher.json(
        f"{GITHUB_API}/search/repositories", {"q": query, "sort": "stars", "order": "desc", "per_page": 15}
    )
    repos = [_repo_from_api(i, min_stars) for i in (data or {}).get("items", []) if not i.get("fork")]
    strong = [r for r in repos if not r.below_threshold]
    return strong[:limit] if strong else repos[: min(limit, 3)]


def github_repo(fetcher: Fetcher, full_name: str, *, min_stars: int = 50) -> PocRepo | None:
    data = fetcher.json(f"{GITHUB_API}/repos/{full_name}")
    return _repo_from_api(data, min_stars) if data else None


def _file_kind(path: str, text: str = "") -> str:
    low = path.lower()
    if low.rsplit("/", 1)[-1].startswith("readme"):
        return "readme"
    if low.endswith((".yaml", ".yml")) and ("http:" in text or "requests:" in text or "matchers" in text):
        return "nuclei"
    if low.endswith((".md", ".txt")):
        return "doc"
    return "code"


def _score(path: str, size: int) -> float:
    low = path.lower()
    name = low.rsplit("/", 1)[-1]
    score = 0.0
    if name.startswith("readme"):
        score += 100
    if low.endswith((".yaml", ".yml")) and any(h in low for h in ("cve", "nuclei", "template")):
        score += 60  # nuclei templates state paths and matchers precisely
    score += sum(8 for h in _NAME_HINTS if h in name)
    score -= low.count("/") * 4
    if size > 30_000:
        score -= 10
    return score


def repo_material(
    fetcher: Fetcher, repo: PocRepo, *, max_files: int = 6, max_chars: int = 90_000, per_file: int = 24_000
) -> list[PocFile]:
    tree = fetcher.json(f"{GITHUB_API}/repos/{repo.full_name}/git/trees/{repo.default_branch}", {"recursive": "1"})
    candidates: list[tuple[float, str, int]] = []
    for node in (tree or {}).get("tree", []):
        if node.get("type") != "blob":
            continue
        path, size = str(node.get("path", "")), int(node.get("size", 0))
        low = path.lower()
        if any(f"/{d}/" in f"/{low}" for d in _SKIP_DIRS) or size == 0 or size > 200_000:
            continue
        if low.rsplit("/", 1)[-1].startswith(_SKIP_NAMES):
            continue
        ext = "." + low.rsplit(".", 1)[-1] if "." in low.rsplit("/", 1)[-1] else ""
        if ext not in _TEXT_EXT and not low.rsplit("/", 1)[-1].startswith("readme"):
            continue
        candidates.append((_score(path, size), path, size))
    candidates.sort(key=lambda c: (-c[0], c[1]))
    files: list[PocFile] = []
    total = 0
    for _, path, size in candidates[: max_files * 2]:
        if len(files) >= max_files or total >= max_chars:
            break
        text = fetcher.text(f"{RAW}/{repo.full_name}/{repo.default_branch}/{path}", max_bytes=per_file)
        if not text or not text.strip():
            continue
        files.append(PocFile(path=path, size=size, text=text, kind=_file_kind(path, text)))
        total += len(text)
    return files


def find_cves(*texts: str) -> list[str]:
    seen: list[str] = []
    for text in texts:
        for match in re.findall(r"CVE-\d{4}-\d{4,7}", text or "", flags=re.I):
            cve = match.upper()
            if cve not in seen:
                seen.append(cve)
    return seen
