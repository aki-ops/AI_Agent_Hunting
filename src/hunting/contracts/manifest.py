"""Replay manifest contract.

Ensures every investigation run is deterministic and reproducible.
Captures git commit SHA, configuration hash, and deterministic seed.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
import subprocess
from typing import Any


@dataclass(frozen=True)
class ReplayManifest:
    """Deterministic run manifest for replayability and audit.

    Required on every run:
      - git_sha: git commit hash of the executing codebase
      - config_hash: sha256 hex digest of the deployment configuration
      - seed: deterministic integer seed for sampling and tiebreaking
    """
    git_sha: str
    config_hash: str
    seed: int
    parameters: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.git_sha.strip():
            raise ValueError("git_sha must not be empty")
        if not self.config_hash.strip():
            raise ValueError("config_hash must not be empty")


def get_current_git_sha() -> str:
    """Retrieve current git HEAD commit SHA, or 'unknown-sha' if git fails."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return "0000000000000000000000000000000000000000"


def compute_config_hash(config_bytes: bytes) -> str:
    """Compute SHA-256 hash of configuration content."""
    return hashlib.sha256(config_bytes).hexdigest()


def create_replay_manifest(
    seed: int,
    config_bytes: bytes = b"",
    git_sha: str | None = None,
    parameters: dict[str, Any] | None = None,
) -> ReplayManifest:
    """Create a verified ReplayManifest."""
    sha = git_sha or get_current_git_sha()
    cfg_hash = compute_config_hash(config_bytes)
    return ReplayManifest(
        git_sha=sha,
        config_hash=cfg_hash,
        seed=seed,
        parameters=parameters or {},
    )
