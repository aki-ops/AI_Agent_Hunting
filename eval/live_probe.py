"""Honest BOTS v2 / Splunk live-readiness probe.

A skipped live test is not a pass. This probe always runs and records the
exact blocker when the provider or corpus is unreachable.
"""
from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

DEFAULT_SPLUNK_URL = "https://localhost:8089"


@dataclass(frozen=True)
class LiveReadinessProbe:
    available: bool
    splunk_url: str
    bots_index: str
    credentials_present: bool
    tcp_reachable: bool
    http_ok: bool
    index_present: bool | None
    blocker: str
    live_claim_allowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "splunk_url": self.splunk_url,
            "bots_index": self.bots_index,
            "credentials_present": self.credentials_present,
            "tcp_reachable": self.tcp_reachable,
            "http_ok": self.http_ok,
            "index_present": self.index_present,
            "blocker": self.blocker,
            "live_claim_allowed": self.live_claim_allowed,
        }


def _splunk_url() -> str:
    return (
        os.environ.get("SPLUNK_URL")
        or os.environ.get("SPLUNK_HOST")
        or DEFAULT_SPLUNK_URL
    ).rstrip("/")


def _credentials() -> tuple[str, str] | None:
    token = os.environ.get("SPLUNK_TOKEN", "").strip()
    user = os.environ.get("SPLUNK_USERNAME", "").strip() or "admin"
    password = os.environ.get("SPLUNK_PASSWORD", "").strip()
    if token:
        return ("Bearer", token)
    if password:
        return (user, password)
    # Default local docker pair is not a configured credential unless the host answers.
    return (user, "12345678")


def _tcp_reachable(url: str, timeout: float = 2.0) -> tuple[bool, str]:
    parsed = urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 8089)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, ""
    except OSError as exc:
        return False, f"{host}:{port} {type(exc).__name__}: {exc}"


def probe_bots_v2(*, timeout: float = 3.0) -> LiveReadinessProbe:
    url = _splunk_url()
    index = os.environ.get("SPLUNK_INDEX", "botsv2")
    env_set = any(os.environ.get(name, "").strip() for name in (
        "SPLUNK_URL", "SPLUNK_HOST", "SPLUNK_TOKEN", "SPLUNK_USERNAME", "SPLUNK_PASSWORD", "SPLUNK_INDEX",
    ))
    tcp_ok, tcp_error = _tcp_reachable(url, timeout=min(timeout, 2.0))
    http_ok = False
    index_present: bool | None = None
    http_error = ""
    if tcp_ok:
        try:
            import requests
            auth = _credentials()
            response = requests.get(
                f"{url}/services/server/info",
                params={"output_mode": "json"},
                auth=None if auth and auth[0] == "Bearer" else auth,
                headers={"Authorization": f"Bearer {auth[1]}"} if auth and auth[0] == "Bearer" else None,
                verify=False,
                timeout=timeout,
            )
            http_ok = response.status_code == 200
            if not http_ok:
                http_error = f"HTTP {response.status_code}"
            else:
                idx = requests.get(
                    f"{url}/services/data/indexes/{index}",
                    params={"output_mode": "json"},
                    auth=None if auth and auth[0] == "Bearer" else auth,
                    headers={"Authorization": f"Bearer {auth[1]}"} if auth and auth[0] == "Bearer" else None,
                    verify=False,
                    timeout=timeout,
                )
                index_present = idx.status_code == 200
        except Exception as exc:
            http_error = f"{type(exc).__name__}: {exc}"
    blockers = []
    if not env_set:
        blockers.append("SPLUNK_* environment variables unset")
    if not tcp_ok:
        blockers.append(f"Splunk REST {url} unreachable ({tcp_error})")
    elif not http_ok:
        blockers.append(f"Splunk REST {url} did not authenticate ({http_error or 'non-200'})")
    elif index_present is False:
        blockers.append(f"index {index} not present on {url}")
    available = tcp_ok and http_ok and index_present is True
    if available:
        blocker = ""
    else:
        blocker = "; ".join(blockers) or f"BOTS v2 live path not ready at {url}"
    return LiveReadinessProbe(
        available=available,
        splunk_url=url,
        bots_index=index,
        credentials_present=env_set,
        tcp_reachable=tcp_ok,
        http_ok=http_ok,
        index_present=index_present,
        blocker=blocker,
        live_claim_allowed=available,
    )


__all__ = ["LiveReadinessProbe", "probe_bots_v2"]
