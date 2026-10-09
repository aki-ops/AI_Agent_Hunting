"""Telemetry adapters. The CDB (SQLite) adapter is the only one kept on this branch;
the live Splunk adapter lives on branch ``splunk-adapter``."""
from hunting.adapters.cdb_adapter import CdbAdapter

__all__ = ["CdbAdapter"]
