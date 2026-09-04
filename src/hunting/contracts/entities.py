from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EntityKind(str, Enum):
    HOST = "host"
    ACCOUNT = "account"
    PROCESS = "process"
    IP = "ip"
    FILE = "file"
    DOMAIN = "domain"
    ANY = "ANY"


@dataclass(frozen=True)
class Host:
    kind: EntityKind = EntityKind.HOST
    name: str = ""  # normalized short name, e.g. "DESKTOP-ABC123"


@dataclass(frozen=True)
class Account:
    kind: EntityKind = EntityKind.ACCOUNT
    username: str = ""  # e.g. "john.doe" — domain will be added later


@dataclass(frozen=True)
class Process:
    kind: EntityKind = EntityKind.PROCESS
    host: str = ""   # machine running this process
    pid: int = 0     # Process ID
    time: str = ""   # first_seen_ts — required because PIDs are reused across time


@dataclass(frozen=True)
class IPAddress:
    kind: EntityKind = EntityKind.IP
    address: str = ""  # normalized IP address


@dataclass(frozen=True)
class File:
    kind: EntityKind = EntityKind.FILE
    host: str = ""   # machine containing this file — needed because same path on 2 hosts = 2 entities
    path: str = ""   # normalized path, e.g. "c:\\windows\\system32\\cmd.exe"


@dataclass(frozen=True)
class Domain:
    kind: EntityKind = EntityKind.DOMAIN
    name: str = ""   # lowercased FQDN, no trailing dot, e.g. "evil.com"


@dataclass(frozen=True)
class AnyEntity:
    """Wildcard entity — used ONLY in Cell.entity for BroadSweep wildcard queries.

    May NEVER appear in:
      - Observation.entities
      - Expectation.entity_ref

    Use the module-level ANY constant — do not instantiate this class directly.
    """
    kind: EntityKind = EntityKind.ANY


# Singleton wildcard constant — always use this, never instantiate AnyEntity directly
ANY = AnyEntity()

# Account alias
User = Account

# All valid entity reference types (including wildcard)
EntityRef = Host | Account | Process | IPAddress | File | Domain | AnyEntity

