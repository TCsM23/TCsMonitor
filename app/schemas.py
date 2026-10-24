"""API schemas (Pydantic), kept separate from the DB tables."""
import re
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from .models import CheckType

_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:]*$")


def _utc(v: datetime) -> datetime:
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


class HostCreate(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    address: str = Field(min_length=1, max_length=255)
    check_type: CheckType = CheckType.ping
    port: int | None = Field(default=None, ge=1, le=65535)

    @model_validator(mode="after")
    def check_combo(self) -> "HostCreate":
        if self.check_type == CheckType.tcp and self.port is None:
            raise ValueError("TCP checks need a port")
        if self.check_type == CheckType.http:
            if not self.address.startswith(("http://", "https://")):
                raise ValueError("HTTP checks need a full URL (http:// or https://)")
        elif not _TARGET_RE.match(self.address):
            raise ValueError("Address must be an IP or hostname")
        return self


class HostRead(BaseModel):
    id: int
    name: str
    address: str
    check_type: CheckType
    port: int | None
    enabled: bool


Status = Literal["up", "down", "unknown"]


class HostStatus(HostRead):
    status: Status
    last_latency_ms: float | None
    last_checked: datetime | None
    last_error: str | None
    uptime_24h: float | None
    loss_pct: float | None
    jitter_ms: float | None
    cert_days: int | None
    timings: dict[str, float]


class CheckResultRead(BaseModel):
    timestamp: datetime
    success: bool
    latency_ms: float | None
    error: str | None
    dns_ms: float | None
    connect_ms: float | None
    tls_ms: float | None
    ttfb_ms: float | None

    @field_validator("timestamp")
    @classmethod
    def as_utc(cls, v: datetime) -> datetime:
        return _utc(v)


class TargetIn(BaseModel):
    """A host for a tool (traceroute, MTU). Validated so it can't smuggle in command flags."""
    host: str = Field(min_length=1, max_length=255)

    @field_validator("host")
    @classmethod
    def safe(cls, v: str) -> str:
        v = v.strip()
        if not _TARGET_RE.match(v):
            raise ValueError("Enter an IP address or hostname")
        return v


class DiscoverIn(BaseModel):
    cidr: str = Field(min_length=7, max_length=43)


class SpeedIn(BaseModel):
    url: str | None = None


class DeviceRead(BaseModel):
    mac: str
    ip: str
    vendor: str | None
    known: bool
    first_seen: datetime
    last_seen: datetime

    @field_validator("first_seen", "last_seen")
    @classmethod
    def as_utc(cls, v: datetime) -> datetime:
        return _utc(v)
