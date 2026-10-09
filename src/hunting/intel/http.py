"""Small HTTP client for public intelligence sources (GitHub, NVD).

Design rules (the inputs are untrusted internet content):

* only GET, only to a fixed allow-list of public hosts;
* hard caps on size and time, text only (binary content is refused);
* everything is cached on disk, so reruns do not burn the unauthenticated GitHub quota (60 requests/hour);
* a token (``GITHUB_TOKEN`` / ``NVD_API_KEY``) is optional, sent only to its own host, and never logged.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

ALLOWED_HOSTS = {"api.github.com", "raw.githubusercontent.com", "services.nvd.nist.gov"}
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class IntelError(RuntimeError):
    """A public source could not be read (network, quota, refusal)."""


class Fetcher:
    def __init__(
        self,
        cache_dir: str | Path | None = "artifacts/.cache/intel",
        *,
        ttl: int = 86400,
        timeout: int = 25,
        max_bytes: int = 2_000_000,
        github_token: str | None = None,
        nvd_key: str | None = None,
        session: requests.Session | None = None,
    ) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.ttl = ttl
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.github_token = github_token if github_token is not None else os.environ.get("GITHUB_TOKEN", "")
        self.nvd_key = nvd_key if nvd_key is not None else os.environ.get("NVD_API_KEY", "")
        self.session = session or requests.Session()
        self.requests_made = 0
        self.cache_hits = 0

    # -- cache -----------------------------------------------------------------------
    def _path(self, key: str) -> Path | None:
        if self.cache_dir is None:
            return None
        return self.cache_dir / (hashlib.sha256(key.encode("utf-8")).hexdigest()[:40] + ".json")

    def _cached(self, key: str) -> Any | None:
        path = self._path(key)
        if path is None or not path.exists():
            return None
        try:
            blob = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if time.time() - float(blob.get("t", 0)) > self.ttl:
            return None
        self.cache_hits += 1
        return blob.get("body")

    def _store(self, key: str, body: Any) -> None:
        path = self._path(key)
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"t": time.time(), "url": key.split("|", 1)[0], "body": body}), encoding="utf-8")
        except OSError:
            pass

    # -- transport -----------------------------------------------------------------------
    def _headers(self, host: str, extra: dict[str, str] | None) -> dict[str, str]:
        headers = {"User-Agent": "ai-agent-hunting-prepare/0.3 (defensive threat-hunting research)"}
        if host == "api.github.com":
            headers["Accept"] = "application/vnd.github+json"
            if self.github_token:
                headers["Authorization"] = f"Bearer {self.github_token}"
        if host == "services.nvd.nist.gov" and self.nvd_key:
            headers["apiKey"] = self.nvd_key
        headers.update(extra or {})
        return headers

    def _get(self, url: str, params: dict[str, Any] | None, extra: dict[str, str] | None) -> requests.Response:
        host = urlparse(url).hostname or ""
        if host not in ALLOWED_HOSTS or not url.startswith("https://"):
            raise IntelError(f"refusing to fetch {url!r}: host not in the allow-list {sorted(ALLOWED_HOSTS)}")
        last: Exception | None = None
        for attempt in range(3):
            try:
                self.requests_made += 1
                resp = self.session.get(
                    url, params=params, headers=self._headers(host, extra), timeout=self.timeout, stream=True
                )
            except requests.RequestException as exc:
                last = exc
                time.sleep(1.5 * (attempt + 1))
                continue
            if resp.status_code in (403, 429) and resp.headers.get("x-ratelimit-remaining") == "0":
                reset = resp.headers.get("x-ratelimit-reset", "?")
                raise IntelError(
                    f"rate limit reached for {host} (resets at epoch {reset}); set GITHUB_TOKEN to raise the quota"
                )
            if resp.status_code >= 500:
                last = IntelError(f"{host} answered {resp.status_code}")
                time.sleep(1.5 * (attempt + 1))
                continue
            return resp
        raise IntelError(f"could not reach {host}: {last}")

    def _read(self, resp: requests.Response, limit: int) -> bytes:
        data = b""
        for chunk in resp.iter_content(chunk_size=16384):
            data += chunk
            if len(data) > limit:
                raise IntelError(f"response larger than {limit} bytes: refused")
        return data

    # -- public ----------------------------------------------------------------------------
    def json(self, url: str, params: dict[str, Any] | None = None, *, headers: dict[str, str] | None = None) -> Any:
        key = f"{url}|{json.dumps(params or {}, sort_keys=True)}"
        hit = self._cached(key)
        if hit is not None:
            return hit
        resp = self._get(url, params, headers)
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise IntelError(f"{url} answered HTTP {resp.status_code}")
        body = json.loads(self._read(resp, self.max_bytes).decode("utf-8", errors="replace"))
        self._store(key, body)
        return body

    def text(self, url: str, *, max_bytes: int = 60_000) -> str | None:
        """Fetch a text file; ``None`` for 404 or binary content. Content is truncated, never executed."""
        key = f"{url}|text|{max_bytes}"
        hit = self._cached(key)
        if hit is not None:
            return hit or None
        resp = self._get(url, None, None)
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise IntelError(f"{url} answered HTTP {resp.status_code}")
        raw = b""
        for chunk in resp.iter_content(chunk_size=16384):
            raw += chunk
            if len(raw) >= max_bytes:
                raw = raw[:max_bytes]
                break
        resp.close()
        if b"\x00" in raw[:2048]:
            self._store(key, "")
            return None
        text = _CONTROL.sub("", raw.decode("utf-8", errors="replace"))
        self._store(key, text)
        return text
