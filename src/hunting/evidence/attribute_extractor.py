"""Contextual Attribute Extractor for Semi-Structured Threat Telemetry.

Extracts semantic attributes (e.g., software_version, file_hash, command_flags)
embedded within file paths, command lines, image paths, and raw logs,
bridging the gap between semi-structured provider telemetry and structured hunt answers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from hunting.contracts.observations import Observation


@dataclass
class ExtractedAttribute:
    """Represents an attribute extracted from telemetry fields."""
    value: str
    attribute_type: str
    source_field: str
    observation_id: str
    confidence: float = 1.0
    context: str = ""
    query_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "attribute_type": self.attribute_type,
            "source_field": self.source_field,
            "observation_id": self.observation_id,
            "confidence": self.confidence,
            "context": self.context,
            "query_id": self.query_id,
        }


# Regex patterns for software version extraction from filenames, paths, and commands
_VERSION_FILENAME_PATTERNS = [
    # Package / installer with version: torbrowser-install-7.0.4_en-US.exe, setup_1.2.3.exe
    re.compile(
        r"(?i)[a-zA-Z0-9_.-]*(?:install|setup|browser|client|desktop|server|agent|update|release)[-_ ]*(\d+\.\d+(?:\.\d+)*)",
        re.IGNORECASE,
    ),
    # Version directory or binary pattern: /SomeApp-v2.1.0/ or App_v2.0.1
    re.compile(
        r"(?i)[a-zA-Z0-9_.-]+[-_ ]+v?(\d+\.\d+(?:\.\d+)*)",
        re.IGNORECASE,
    ),
    # Explicit version parameter in command line: --version 7.0.4, /version:1.2.3
    re.compile(
        r"(?i)(?:--?version|/version)[=: ]+[\"']?(\d+\.\d+(?:\.\d+)*)[\"']?",
        re.IGNORECASE,
    ),
]

_HASH_PATTERNS = {
    "sha256": re.compile(r"\b([a-fA-F0-9]{64})\b"),
    "sha1": re.compile(r"\b([a-fA-F0-9]{40})\b"),
    "md5": re.compile(r"\b([a-fA-F0-9]{32})\b"),
}


def _is_valid_semver(candidate: str) -> bool:
    """Validate that candidate string is plausible software version, not IP or schema."""
    cand = candidate.strip().rstrip("._-")
    if not cand:
        return False
    # Exclude single numbers (e.g. Sysmon schema version '4')
    if "." not in cand and "-" not in cand:
        return False
    # Exclude IP addresses
    parts = cand.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return False
    # Must start with a digit
    if not cand[0].isdigit():
        return False
    return True


def extract_attributes_from_observation(
    obs: Observation,
    attribute_type: str,
    target_keyword: str = "",
) -> list[ExtractedAttribute]:
    """Extract candidate attributes from an observation based on attribute_type."""
    results: list[ExtractedAttribute] = []
    obs_id = obs.id
    query_id = obs.query_id or (obs.provenance.query_id if obs.provenance else "")

    fields_dict = dict(obs.fields)
    # Also check native_fields and raw_event
    if hasattr(obs, "raw_event") and isinstance(obs.raw_event, dict):
        for k, v in obs.raw_event.items():
            if k not in fields_dict and v not in (None, ""):
                fields_dict[k] = v

    attr_lower = attribute_type.lower()

    if attr_lower in ("software_version", "version", "file_version"):
        # 1. First check explicit version fields
        for vf in ("software_version", "ProductVersion", "FileVersion", "Version", "version"):
            val = fields_dict.get(vf)
            if val is not None:
                val_str = str(val).strip()
                if val_str and val_str not in ("-", "unknown", "None") and _is_valid_semver(val_str):
                    proc_or_img = str(fields_dict.get("Image") or fields_dict.get("image") or fields_dict.get("process_name") or "").lower()
                    kw_in_proc = bool(target_keyword and target_keyword.lower() in proc_or_img)
                    # If target keyword is Tor, but process is firefox.exe, confidence is lower than a direct installer
                    relevance = 1.0 if kw_in_proc else (0.85 if target_keyword else 0.9)
                    results.append(ExtractedAttribute(
                        value=val_str,
                        attribute_type="software_version",
                        source_field=vf,
                        observation_id=obs_id,
                        confidence=relevance,
                        context=f"{vf}: {val_str}",
                        query_id=query_id,
                    ))

        # 2. Extract from rich text fields (Path, TargetFilename, CommandLine, Image, _raw)
        candidate_fields = (
            "TargetFilename", "target_filename", "Path", "path", "file_path",
            "CommandLine", "cmdline", "Image", "image", "raw_ref", "_raw",
        )
        for cf in candidate_fields:
            raw_text = str(fields_dict.get(cf) or "")
            if not raw_text:
                continue

            # Prioritize matching paths/commands that match the target keyword (e.g. 'tor')
            has_kw = bool(target_keyword and target_keyword.lower() in raw_text.lower())
            is_installer = any(k in raw_text.lower() for k in ("install", "setup"))
            if has_kw and is_installer:
                base_conf = 1.20  # Authoritative installer version for requested target tool
            elif has_kw:
                base_conf = 1.05
            else:
                base_conf = 0.80 if target_keyword else 0.85

            for pat in _VERSION_FILENAME_PATTERNS:
                for match in pat.finditer(raw_text):
                    extracted = match.group(1).strip().rstrip("._-")
                    if _is_valid_semver(extracted):
                        # Avoid duplicates for same value
                        if not any(r.value == extracted for r in results):
                            snippet = raw_text[max(0, match.start() - 20):min(len(raw_text), match.end() + 20)]
                            results.append(ExtractedAttribute(
                                value=extracted,
                                attribute_type="software_version",
                                source_field=cf,
                                observation_id=obs_id,
                                confidence=base_conf,
                                context=f"...{snippet}...",
                                query_id=query_id,
                            ))

    elif attr_lower in ("file_hash", "hash", "sha256", "sha1", "md5"):
        candidate_fields = ("Hashes", "hashes", "hash", "CommandLine", "cmdline", "_raw")
        target_algo = "sha256" if "256" in attr_lower else ("sha1" if "sha1" in attr_lower else ("md5" if "md5" in attr_lower else "any"))
        for cf in candidate_fields:
            raw_text = str(fields_dict.get(cf) or "")
            if not raw_text:
                continue
            for algo, pat in _HASH_PATTERNS.items():
                if target_algo != "any" and target_algo != algo:
                    continue
                for match in pat.finditer(raw_text):
                    h_val = match.group(1)
                    if not any(r.value == h_val for r in results):
                        results.append(ExtractedAttribute(
                            value=h_val,
                            attribute_type=algo,
                            source_field=cf,
                            observation_id=obs_id,
                            confidence=0.95,
                            context=f"{algo}: {h_val}",
                            query_id=query_id,
                        ))

    return results


def extract_best_attribute(
    observations: Iterable[Observation],
    attribute_type: str,
    target_keyword: str = "",
) -> ExtractedAttribute | None:
    """Scan observations and return the highest-confidence attribute matching the criteria."""
    all_extracted: list[ExtractedAttribute] = []
    for obs in observations:
        extracted = extract_attributes_from_observation(obs, attribute_type, target_keyword=target_keyword)
        all_extracted.extend(extracted)

    if not all_extracted:
        return None

    # Sort primarily by confidence, secondarily by value length (prefer more specific versions like 7.0.4 over 7.0)
    all_extracted.sort(key=lambda a: (-a.confidence, -len(a.value)))
    return all_extracted[0]


__all__ = [
    "ExtractedAttribute",
    "extract_attributes_from_observation",
    "extract_best_attribute",
]
