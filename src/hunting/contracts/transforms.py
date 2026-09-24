"""Modular semantic transforms and constraint evaluators (v9).

Replaces ad-hoc string matching and heuristics inside provider adapters with
typed, versioned transform rules that evaluate constraints deterministically
for both native query generation and ProofEngine verification.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SemanticTransformResult:
    """Outcome of evaluating a transform against row fields."""
    matched: bool
    diagnostic: str = ""


class SemanticTransform:
    """Base specification for versioned semantic transforms."""

    name: str = "base"
    version: str = "1.0"

    def matches_constraint(self, key: str, value: Any) -> bool:
        """Return True if this transform handles the specified constraint key and value."""
        return False

    def supports_constraint_key(self, key: str) -> bool:
        """Return whether this transform can evaluate a constraint key."""
        return False

    def evaluates_row(
        self,
        row_fields: dict[str, str],
        key: str,
        value: Any,
        operator: str = "equals",
    ) -> bool:
        """Evaluate whether an observed telemetry row satisfies the transform rule."""
        return False

    def get_retrieval_terms(self, key: str, value: Any) -> tuple[str, ...]:
        """Return provider-neutral retrieval terms/aliases for this transform."""
        return ()

    def to_sql_predicate(
        self,
        target_column: str,
        key: str,
        value: Any,
        operator: str = "equals",
    ) -> tuple[str, list[Any]]:
        """Generate SQL WHERE condition and parameters for the transform."""
        return "", []

    def to_spl_predicate(
        self,
        target_field: str,
        key: str,
        value: Any,
        operator: str = "equals",
    ) -> str:
        """Generate Splunk SPL filter condition for the transform."""
        return ""


class NestedKeyExtractionTransform(SemanticTransform):
    """Provider-neutral marker for extracting a census-backed payload key.

    The provider compiler supplies the native implementation (for example
    ``spath`` in Splunk).  The key is never inferred from this class; it must
    come from a nested-payload census field admitted by the validator.
    """

    name = "extract_nested_key"
    version = "1.0"

    def supports_constraint_key(self, key: str) -> bool:
        return True

    def matches_constraint(self, key: str, value: Any) -> bool:
        return False

    def evaluates_row(
        self,
        row_fields: dict[str, str],
        key: str,
        value: Any,
        operator: str = "equals",
    ) -> bool:
        # Extraction is performed by the provider adapter.  This transform is
        # not itself a semantic proof evaluator.
        return False


class PowerShellInterpreterTransform(SemanticTransform):
    """Detects and verifies PowerShell interpreter execution."""

    name = "powershell_interpreter"
    version = "1.0"

    def supports_constraint_key(self, key: str) -> bool:
        return str(key).strip().casefold() in {
            "command_interpreter", "interpreter", "shell", "process_type",
            "cmdline", "image", "process", "process_name",
        }

    def matches_constraint(self, key: str, value: Any) -> bool:
        k = str(key).strip().casefold()
        v = str(value or "").strip().casefold()
        if k in {"command_interpreter", "interpreter", "shell", "process_type"}:
            return "powershell" in v or "pwsh" in v
        if k in {"cmdline", "image", "process", "process_name"}:
            return v in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}
        return False

    def evaluates_row(
        self,
        row_fields: dict[str, str],
        key: str,
        value: Any,
        operator: str = "equals",
    ) -> bool:
        cmdline = row_fields.get("cmdline", "").strip().casefold()
        image = row_fields.get("image", "").strip().casefold()
        process = row_fields.get("process", "").strip().casefold()
        process_name = row_fields.get("process_name", "").strip().casefold()

        # Check explicit process / image / process_name first
        proc_identifiers = [p for p in (image, process, process_name) if p]
        if proc_identifiers:
            return any("powershell" in p or "pwsh" in p for p in proc_identifiers)

        # If only cmdline is available, check executable name (first token or path)
        if cmdline:
            first_token = cmdline.strip()
            if first_token.startswith('"'):
                end_quote = first_token.find('"', 1)
                if end_quote != -1:
                    first_token = first_token[1:end_quote]
            elif first_token.startswith("'"):
                end_quote = first_token.find("'", 1)
                if end_quote != -1:
                    first_token = first_token[1:end_quote]
            else:
                first_token = first_token.split()[0]
            first_token = first_token.replace("\\", "/").split("/")[-1]
            return "powershell" in first_token or "pwsh" in first_token

        return False

    def to_sql_predicate(
        self,
        target_column: str,
        key: str,
        value: Any,
        operator: str = "equals",
    ) -> tuple[str, list[Any]]:
        col = target_column or "cmdline"
        return (
            f"({col} LIKE ? OR {col} LIKE ?)",
            ["%powershell%", "%pwsh%"],
        )

    def to_spl_predicate(
        self,
        target_field: str,
        key: str,
        value: Any,
        operator: str = "equals",
    ) -> str:
        fld = target_field or "cmdline"
        return f'({fld}="*powershell*" OR {fld}="*pwsh*")'


class PowerShellEncodedTransform(SemanticTransform):
    """Detects and verifies PowerShell command-line encoding flags."""

    name = "powershell_encoded"
    version = "1.0"

    ENCODED_FLAGS = ("-enc", "-encodedcommand", "-e ", "-ec ", "/enc", "/encodedcommand", "/e ", "/ec ")

    def supports_constraint_key(self, key: str) -> bool:
        return str(key).strip().casefold() in {"encoding", "encoding_state", "encoded"}

    def matches_constraint(self, key: str, value: Any) -> bool:
        k = str(key).strip().casefold()
        v = str(value or "").strip().casefold()
        if k in {"encoding", "encoding_state", "encoded"}:
            return v in {"encoded", "base64", "true", "yes"}
        return False

    def evaluates_row(
        self,
        row_fields: dict[str, str],
        key: str,
        value: Any,
        operator: str = "equals",
    ) -> bool:
        cmdline = row_fields.get("cmdline", "").casefold()
        if not cmdline:
            return False
        return any(flag in cmdline for flag in self.ENCODED_FLAGS)

    def to_sql_predicate(
        self,
        target_column: str,
        key: str,
        value: Any,
        operator: str = "equals",
    ) -> tuple[str, list[Any]]:
        conditions = [
            f"{target_column} LIKE '%-enc%'",
            f"{target_column} LIKE '%-encodedcommand%'",
            f"{target_column} LIKE '%-e %'",
            f"{target_column} LIKE '%-ec %'",
        ]
        return f"({' OR '.join(conditions)})", []

    def to_spl_predicate(
        self,
        target_field: str,
        key: str,
        value: Any,
        operator: str = "equals",
    ) -> str:
        return f'({target_field}="*-enc*" OR {target_field}="*-encodedcommand*" OR {target_field}="*-e *" OR {target_field}="*-ec *")'


class BashInterpreterTransform(SemanticTransform):
    """Detects and verifies Unix Bash/sh interpreter execution."""

    name = "bash_interpreter"
    version = "1.0"

    def supports_constraint_key(self, key: str) -> bool:
        return str(key).strip().casefold() in {"command_interpreter", "interpreter", "shell"}

    def matches_constraint(self, key: str, value: Any) -> bool:
        k = str(key).strip().casefold()
        v = str(value or "").strip().casefold()
        if k in {"command_interpreter", "interpreter", "shell"}:
            return v in {"bash", "sh", "zsh", "dash"}
        return False

    def evaluates_row(
        self,
        row_fields: dict[str, str],
        key: str,
        value: Any,
        operator: str = "equals",
    ) -> bool:
        cmdline = row_fields.get("cmdline", "").strip().casefold()
        image = row_fields.get("image", "").strip().casefold()
        process = row_fields.get("process", "").strip().casefold()
        process_name = row_fields.get("process_name", "").strip().casefold()

        proc_identifiers = [p for p in (image, process, process_name) if p]
        if proc_identifiers:
            return any(
                p.endswith("/bash") or p.endswith("/sh") or p in {"bash", "sh", "bash.exe", "sh.exe"} or "/bash " in p
                for p in proc_identifiers
            )

        if cmdline:
            first_token = cmdline.strip()
            if first_token.startswith('"'):
                end_quote = first_token.find('"', 1)
                if end_quote != -1:
                    first_token = first_token[1:end_quote]
            elif first_token.startswith("'"):
                end_quote = first_token.find("'", 1)
                if end_quote != -1:
                    first_token = first_token[1:end_quote]
            else:
                first_token = first_token.split()[0]
            first_token = first_token.replace("\\", "/").split("/")[-1]
            return first_token in {"bash", "sh", "bash.exe", "sh.exe"}

        return False

    def to_sql_predicate(
        self,
        target_column: str,
        key: str,
        value: Any,
        operator: str = "equals",
    ) -> tuple[str, list[Any]]:
        col = target_column or "cmdline"
        return (f"({col} LIKE ? OR {col} LIKE ?)", ["%bash%", "%sh%"])

    def to_spl_predicate(
        self,
        target_field: str,
        key: str,
        value: Any,
        operator: str = "equals",
    ) -> str:
        fld = target_field or "cmdline"
        return f'({fld}="*bash*" OR {fld}="*sh*")'


_SINGLE_EXTENSION_RE = re.compile(r"^\.[A-Za-z0-9]{1,12}$")
_FILENAME_RE = re.compile(r"^[^\\/\s]+(\.[A-Za-z0-9]{1,12})+$")


def is_literal_telemetry_token(value: Any) -> bool:
    """True when a constraint value is already a path, filename, or single extension.

    Descriptive phrases and playbook alias lists are not telemetry tokens.
    A standalone dotted suffix with two segments (for example a compound
    scenario suffix) is not a single extension and is rejected.
    """
    text = str(value or "").strip()
    if not text or any(ch.isspace() for ch in text):
        return False
    if text.startswith("."):
        return bool(_SINGLE_EXTENSION_RE.fullmatch(text))
    if "/" in text or "\\" in text:
        base = text.replace("\\", "/").rsplit("/", 1)[-1]
        return bool(base) and ("." in base) and " " not in base
    return bool(_FILENAME_RE.fullmatch(text))


class FileTypeSemanticTransform(SemanticTransform):
    """Pass through literal file identity; do not expand product names to suffixes."""

    name = "file_type_expansion"
    version = "2.0"

    def supports_constraint_key(self, key: str) -> bool:
        return str(key).strip().casefold() in {
            "file_extension", "extension", "file_name", "file_path",
            "filename", "path", "file_type", "kind", "format",
        }

    def get_retrieval_terms(self, key: str, value: Any) -> tuple[str, ...]:
        if not self.supports_constraint_key(key):
            return ()
        text = str(value or "").strip()
        if is_literal_telemetry_token(text):
            return (text,)
        return ()

    def matches_constraint(self, key: str, value: Any) -> bool:
        if not self.supports_constraint_key(key):
            return False
        return bool(self.get_retrieval_terms(key, value))

    def evaluates_row(
        self,
        row_fields: dict[str, str],
        key: str,
        value: Any,
        operator: str = "equals",
    ) -> bool:
        terms = self.get_retrieval_terms(key, value)
        if not terms:
            return False
        file_fields = (
            "file_name", "file_path", "TargetFilename", "target_path", "path",
            "filename", "object", "file", "target_filename",
        )
        values_to_check = [str(row_fields[f]).casefold() for f in file_fields if f in row_fields and row_fields[f]]
        if "_raw" in row_fields and row_fields["_raw"]:
            values_to_check.append(str(row_fields["_raw"]).casefold())

        for v in values_to_check:
            for term in terms:
                if term.casefold() in v:
                    return True
        return False

    def to_sql_predicate(
        self,
        target_column: str,
        key: str,
        value: Any,
        operator: str = "equals",
    ) -> tuple[str, list[Any]]:
        terms = self.get_retrieval_terms(key, value)
        if not terms:
            return "", []
        col = target_column or "file_path"
        conditions = [f"{col} LIKE ?" for _ in terms]
        params = [f"%{term}%" for term in terms]
        return f"({' OR '.join(conditions)})", params

    def to_spl_predicate(
        self,
        target_field: str,
        key: str,
        value: Any,
        operator: str = "equals",
    ) -> str:
        terms = self.get_retrieval_terms(key, value)
        if not terms:
            return ""
        fld = target_field or "file_path"
        predicates = [f'{fld}="*{term}*"' for term in terms]
        return f"({' OR '.join(predicates)})"


_CANONICAL_TRANSFORMS: tuple[SemanticTransform, ...] = (
    NestedKeyExtractionTransform(),
    PowerShellInterpreterTransform(),
    PowerShellEncodedTransform(),
    BashInterpreterTransform(),
    FileTypeSemanticTransform(),
)

_TRANSFORM_ALIASES: dict[tuple[str, str], str] = {
    ("command_interpreter", "powershell"): "powershell_interpreter",
    ("command_interpreter", "pwsh"): "powershell_interpreter",
    ("encoding_state", "encoded"): "powershell_encoded",
    ("encoding", "encoded"): "powershell_encoded",
    ("encoding_state", "base64"): "powershell_encoded",
    ("encoding", "base64"): "powershell_encoded",
    ("command_interpreter", "bash"): "bash_interpreter",
    ("command_interpreter", "sh"): "bash_interpreter",
}


def get_transform_for_constraint(key: str, value: Any) -> SemanticTransform | None:
    """Resolve the canonical semantic transform matching a given constraint."""
    for transform in _CANONICAL_TRANSFORMS:
        if transform.matches_constraint(key, value):
            return transform
    return None


def get_transform_by_name(name: str) -> SemanticTransform | None:
    """Resolve an explicitly declared transform ID.

    Source-profiler output is untrusted.  Callers that validate a proposal
    must use this function instead of treating an arbitrary model string as
    executable semantic logic.
    """
    normalized = str(name or "").strip().casefold()
    if not normalized:
        return None
    return next(
        (transform for transform in _CANONICAL_TRANSFORMS
         if transform.name.casefold() == normalized),
        None,
    )


def list_transform_specs() -> tuple[dict[str, Any], ...]:
    """Expose the bounded transform catalog to planning components."""
    return tuple(
        {
            "id": transform.name,
            "version": transform.version,
        }
        for transform in _CANONICAL_TRANSFORMS
    )


def canonical_transform_name(
    name: str,
    key: str,
    value: Any,
) -> str | None:
    """Return a registered transform ID, accepting only known legacy aliases."""
    explicit = str(name or "").strip().casefold()
    if explicit:
        if get_transform_by_name(explicit) is not None:
            return explicit
        alias = _TRANSFORM_ALIASES.get((str(key).strip().casefold(), explicit))
        if alias and get_transform_by_name(alias) is not None:
            return alias
        return None

    inferred = get_transform_for_constraint(key, value)
    return inferred.name if inferred is not None else None


def evaluate_constraint_against_row(
    row_fields: dict[str, str],
    constraint_key: str,
    constraint_value: Any,
    operator: str = "equals",
    retrieval_terms: tuple[str, ...] = (),
) -> bool:
    """Deterministically evaluate whether an observed row satisfies a semantic constraint."""
    k = str(constraint_key).strip().casefold()
    op = str(operator).strip().casefold()
    target_val = str(constraint_value).strip().casefold() if constraint_value is not None else ""

    # 1. Check specialized semantic transforms first
    transform = get_transform_for_constraint(k, constraint_value)
    if transform is not None:
        return transform.evaluates_row(row_fields, k, constraint_value, op)

    # 2. Check retrieval terms if present
    if retrieval_terms:
        for term in retrieval_terms:
            t_norm = str(term).strip().casefold()
            if any(t_norm in str(v).casefold() for v in row_fields.values() if v):
                return True

    # 3. Direct field evaluation
    val_in_row = row_fields.get(k)
    if val_in_row is None:
        aliases = {
            "host": ("host", "hostname", "computername", "dest"),
            "user": ("user", "username", "account", "src_user"),
            "image": ("image", "process", "process_name"),
            "cmdline": ("cmdline", "commandline", "command"),
            "ip": ("ip", "src_ip", "dest_ip", "ip_address"),
            "domain": ("domain", "site", "dest_domain", "query", "url"),
            "file": ("file_name", "targetfilename", "path", "file_path"),
        }
        for field_group in aliases.values():
            if k in field_group:
                for alias in field_group:
                    if alias in row_fields and row_fields[alias]:
                        val_in_row = row_fields[alias]
                        break
            if val_in_row is not None:
                break

    if val_in_row is None:
        return False

    r_norm = str(val_in_row).strip().casefold()

    if op in {"equals", "eq"}:
        return r_norm == target_val
    elif op in {"contains", "like"}:
        return target_val in r_norm
    elif op == "exists":
        return bool(r_norm)
    elif op == "absent":
        return not bool(r_norm)
    elif op == "startswith":
        return r_norm.startswith(target_val)
    elif op == "endswith":
        return r_norm.endswith(target_val)

    return target_val in r_norm


__all__ = [
    "BashInterpreterTransform",
    "FileTypeSemanticTransform",
    "NestedKeyExtractionTransform",
    "PowerShellEncodedTransform",
    "PowerShellInterpreterTransform",
    "SemanticTransform",
    "SemanticTransformResult",
    "evaluate_constraint_against_row",
    "canonical_transform_name",
    "get_transform_by_name",
    "get_transform_for_constraint",
    "is_literal_telemetry_token",
    "list_transform_specs",
]
