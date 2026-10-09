"""Telemetry adapters. The CDB (SQLite) adapter is the only one kept on this branch;
the live Splunk adapter was removed after commit ``4dace56`` (see git history)."""
from hunting.adapters.cdb_adapter import CdbAdapter

__all__ = ["CdbAdapter"]
