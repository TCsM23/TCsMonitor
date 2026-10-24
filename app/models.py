"""Database tables (SQLModel)."""
from datetime import datetime, timezone
from enum import Enum

from sqlmodel import Field, SQLModel


class CheckType(str, Enum):
    ping = "ping"
    tcp = "tcp"
    http = "http"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Host(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str
    address: str  # IP/hostname, or a full URL for http checks
    check_type: CheckType = CheckType.ping
    port: int | None = None  # required for tcp checks
    enabled: bool = True
    created_at: datetime = Field(default_factory=utcnow)


class CheckResult(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    host_id: int = Field(foreign_key="host.id", index=True)
    timestamp: datetime = Field(default_factory=utcnow, index=True)
    success: bool
    latency_ms: float | None = None
    error: str | None = None
    dns_ms: float | None = None
    connect_ms: float | None = None
    tls_ms: float | None = None
    ttfb_ms: float | None = None
    cert_days: int | None = None


class Device(SQLModel, table=True):
    """A device seen on the LAN, keyed by MAC address."""
    mac: str = Field(primary_key=True)
    ip: str
    vendor: str | None = None
    known: bool = False  # you mark trusted devices; unknown new ones raise an alert
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
