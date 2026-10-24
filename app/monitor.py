"""Background monitor loop: run checks, store results, track state, broadcast."""
import asyncio
import logging
import os
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import psutil
from sqlalchemy import Integer, cast, delete
from sqlmodel import Session, func, select

from .checks import CheckOutcome, http_check, ping_host, tcp_check
from .db import engine
from .models import CheckResult, CheckType, Host
from .ws import manager

log = logging.getLogger("tcsmonitor")

INTERVAL_S = int(os.getenv("TCSM_INTERVAL", "10"))  # seconds between rounds
DOWN_AFTER = 3        # consecutive failures before "down"
UP_AFTER = 1          # consecutive successes before "up"
WINDOW = 20           # checks used for loss % and jitter
CERT_WARN_DAYS = 14
HISTORY_DAYS = 7


@dataclass
class HostState:
    status: str = "unknown"
    fails: int = 0
    successes: int = 0
    last: CheckOutcome | None = None
    last_checked: datetime | None = None
    window: deque = field(default_factory=lambda: deque(maxlen=WINDOW))
    cert_warned: bool = False

    def update(self, outcome: CheckOutcome) -> bool:
        """Apply a result; return True if the status changed (hysteresis)."""
        self.last = outcome
        self.last_checked = datetime.now(timezone.utc)
        self.window.append(outcome.latency_ms if outcome.success else None)
        if outcome.success:
            self.successes, self.fails = self.successes + 1, 0
            new = "up" if self.successes >= UP_AFTER else self.status
        else:
            self.fails, self.successes = self.fails + 1, 0
            new = "down" if self.fails >= DOWN_AFTER else self.status
        changed = new != self.status
        self.status = new
        return changed

    @property
    def loss_pct(self) -> float | None:
        if not self.window:
            return None
        lost = sum(1 for v in self.window if v is None)
        return round(100 * lost / len(self.window), 1)

    @property
    def jitter_ms(self) -> float | None:
        """Mean absolute difference between consecutive latencies."""
        vals = [v for v in self.window if v is not None]
        if len(vals) < 2:
            return None
        return round(sum(abs(b - a) for a, b in zip(vals, vals[1:])) / (len(vals) - 1), 2)


@dataclass
class Monitor:
    states: dict[int, HostState] = field(default_factory=dict)
    events: list[dict] = field(default_factory=list)
    rounds: int = 0
    _task: asyncio.Task | None = None
    _wake: asyncio.Event = field(default_factory=asyncio.Event)
    _last_net: tuple[float, int, int] | None = None

    def state(self, host_id: int) -> HostState:
        return self.states.setdefault(host_id, HostState())

    def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="monitor-loop")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def check_now(self) -> None:
        self._wake.set()

    async def emit(self, kind: str, name: str, message: str, status: str = "info",
                   host_id: int | None = None) -> None:
        """Record an event (status change, cert warning, new device) and push it live."""
        event = {"type": "event", "kind": kind, "name": name, "status": status,
                 "message": message, "host_id": host_id,
                 "at": datetime.now(timezone.utc).isoformat()}
        self.events = ([event] + self.events)[:100]
        log.warning("[%s] %s", kind, message)
        await manager.broadcast(event)

    async def _run(self) -> None:
        while True:
            try:
                await self._round()
            except Exception:
                log.exception("monitor round failed")  # never let the loop die
            self._wake.clear()
            try:
                await asyncio.wait_for(self._wake.wait(), INTERVAL_S)
            except asyncio.TimeoutError:
                pass

    async def _round(self) -> None:
        hosts = await asyncio.to_thread(_load_enabled_hosts)
        outcomes = await asyncio.gather(*(self._check(h) for h in hosts))
        await asyncio.to_thread(_save_results, list(zip(hosts, outcomes)))
        self.rounds += 1

        for host, outcome in zip(hosts, outcomes):
            st = self.state(host.id)
            if st.update(outcome):
                msg = f"{host.name} is {st.status.upper()}"
                if st.status == "down" and outcome.error:
                    msg += f" ({outcome.error})"
                await self.emit("status", host.name, msg, st.status, host.id)
            if outcome.cert_days is not None and outcome.cert_days < CERT_WARN_DAYS \
                    and not st.cert_warned:
                st.cert_warned = True
                await self.emit("cert", host.name,
                                f"{host.name} TLS certificate expires in {outcome.cert_days} days",
                                "warning", host.id)

        await manager.broadcast({
            "type": "tick", "round": self.rounds,
            "hosts": [snapshot(h, self.state(h.id)) for h in hosts],
            "system": self.system_stats(),
        })

    async def _check(self, host: Host) -> CheckOutcome:
        if host.check_type == CheckType.tcp:
            return await tcp_check(host.address, host.port or 80)
        if host.check_type == CheckType.http:
            return await http_check(host.address)
        return await ping_host(host.address)

    def system_stats(self) -> dict:
        now = time.monotonic()
        io = psutil.net_io_counters()
        up = down = 0.0
        if self._last_net:
            t0, sent0, recv0 = self._last_net
            dt = max(now - t0, 1e-6)
            up, down = (io.bytes_sent - sent0) / dt, (io.bytes_recv - recv0) / dt
        self._last_net = (now, io.bytes_sent, io.bytes_recv)
        return {"cpu_percent": psutil.cpu_percent(interval=None),
                "mem_percent": psutil.virtual_memory().percent,
                "net_up_bps": round(up), "net_down_bps": round(down),
                "round": self.rounds}


def snapshot(host: Host, st: HostState) -> dict:
    last = st.last
    return {
        "id": host.id, "status": st.status,
        "latency_ms": last.latency_ms if last else None,
        "error": last.error if last else None,
        "timings": last.timings if last else {},
        "cert_days": last.cert_days if last else None,
        "loss_pct": st.loss_pct, "jitter_ms": st.jitter_ms,
        "last_checked": st.last_checked.isoformat() if st.last_checked else None,
    }


# ---- DB helpers (sync; called through asyncio.to_thread) -------------------
def _load_enabled_hosts() -> list[Host]:
    with Session(engine) as s:
        return list(s.exec(select(Host).where(Host.enabled == True)))  # noqa: E712


def _save_results(pairs: list[tuple[Host, CheckOutcome]]) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(days=HISTORY_DAYS)
    with Session(engine) as s:
        for host, o in pairs:
            t = o.timings
            s.add(CheckResult(host_id=host.id, success=o.success, latency_ms=o.latency_ms,
                              error=o.error, dns_ms=t.get("dns"), connect_ms=t.get("connect"),
                              tls_ms=t.get("tls"), ttfb_ms=t.get("ttfb"),
                              cert_days=o.cert_days))
        s.exec(delete(CheckResult).where(CheckResult.timestamp < cutoff))
        s.commit()


def uptime_percent(session: Session, host_id: int, hours: int = 24) -> float | None:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    total, ok = session.exec(
        # cast: otherwise SQLAlchemy types SUM(bool) as bool and 4 successes -> True (1)
        select(func.count(), func.sum(cast(CheckResult.success, Integer)))
        .where(CheckResult.host_id == host_id, CheckResult.timestamp >= since)
    ).one()
    return None if not total else round(100 * (ok or 0) / total, 2)


monitor: Monitor | None = None  # created inside the lifespan
