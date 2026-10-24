"""Network checks. Each returns a CheckOutcome and never raises.

HTTP checks are done by hand over asyncio streams (not httpx) so every stage
can be timed separately: DNS -> TCP handshake -> TLS handshake -> first byte.
"""
import asyncio
import platform
import re
import shutil
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

TIMEOUT_S = 2.0
IS_WINDOWS = platform.system() == "Windows"
_LATENCY_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)


@dataclass
class CheckOutcome:
    success: bool
    latency_ms: float | None = None
    error: str | None = None
    timings: dict[str, float] = field(default_factory=dict)  # dns / connect / tls / ttfb
    cert_days: int | None = None


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 2)


async def resolve(host: str, port: int, timeout: float = TIMEOUT_S) -> tuple[str, float]:
    """DNS lookup on its own, so its time is separate from the connection time."""
    loop = asyncio.get_running_loop()
    start = time.perf_counter()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout
    )
    return infos[0][4][0], _ms(start)


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except (OSError, ssl.SSLError):
        pass


async def tcp_check(host: str, port: int, timeout: float = TIMEOUT_S) -> CheckOutcome:
    """Time the 3-way handshake (SYN, SYN-ACK, ACK)."""
    try:
        ip, dns_ms = await resolve(host, port, timeout)
    except (OSError, asyncio.TimeoutError):
        return CheckOutcome(False, error="DNS lookup failed")
    start = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except asyncio.TimeoutError:
        return CheckOutcome(False, error=f"timeout after {timeout}s", timings={"dns": dns_ms})
    except OSError as exc:
        return CheckOutcome(False, error=exc.strerror or str(exc), timings={"dns": dns_ms})
    connect_ms = _ms(start)
    await _close(writer)
    return CheckOutcome(True, connect_ms, timings={"dns": dns_ms, "connect": connect_ms})


async def ping_host(host: str, timeout: float = TIMEOUT_S) -> CheckOutcome:
    """ICMP echo via the system `ping` command (raw sockets would need admin/root)."""
    if shutil.which("ping") is None:
        return CheckOutcome(False, error="ping command not found on this machine")
    if IS_WINDOWS:
        args = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        args = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]

    start = time.perf_counter()
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout + 1)
    except asyncio.TimeoutError:
        proc.kill()
        return CheckOutcome(False, error="ping timed out")
    elapsed = _ms(start)
    text = out.decode(errors="ignore")

    # Windows ping can exit 0 on "Destination host unreachable", so also require "TTL=".
    ok = proc.returncode == 0 and ("ttl=" in text.lower() or not IS_WINDOWS)
    if not ok:
        last = text.strip().splitlines()[-1] if text.strip() else "no reply"
        return CheckOutcome(False, error=last[:120])
    match = _LATENCY_RE.search(text)
    return CheckOutcome(True, float(match.group(1)) if match else elapsed)


async def http_check(url: str, timeout: float = TIMEOUT_S) -> CheckOutcome:
    """GET a URL by hand, timing DNS, TCP connect, TLS handshake and time to first byte."""
    parts = urlsplit(url)
    https = parts.scheme == "https"
    host = parts.hostname or ""
    port = parts.port or (443 if https else 80)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    timings: dict[str, float] = {}

    try:
        ip, timings["dns"] = await resolve(host, port, timeout)
    except (OSError, asyncio.TimeoutError):
        return CheckOutcome(False, error="DNS lookup failed")

    writer = None
    try:
        start = time.perf_counter()
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        timings["connect"] = _ms(start)

        cert_days = None
        if https:
            ctx = ssl.create_default_context()
            start = time.perf_counter()
            await asyncio.wait_for(writer.start_tls(ctx, server_hostname=host), timeout)
            timings["tls"] = _ms(start)
            cert = writer.get_extra_info("ssl_object").getpeercert()
            if cert and "notAfter" in cert:
                expires = ssl.cert_time_to_seconds(cert["notAfter"])
                cert_days = int((expires - time.time()) // 86400)

        request = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                   "User-Agent: TCsMonitor/1.0\r\nConnection: close\r\n\r\n")
        writer.write(request.encode())
        await writer.drain()
        start = time.perf_counter()
        status_line = await asyncio.wait_for(reader.readline(), timeout + 3)
        timings["ttfb"] = _ms(start)
    except asyncio.TimeoutError:
        return CheckOutcome(False, error="timeout", timings=timings)
    except ssl.SSLCertVerificationError as exc:
        return CheckOutcome(False, error=f"TLS: {exc.verify_message}", timings=timings)
    except (OSError, ssl.SSLError) as exc:
        return CheckOutcome(False, error=getattr(exc, "strerror", None) or str(exc)[:120],
                            timings=timings)
    finally:
        if writer is not None:
            await _close(writer)

    total = round(sum(timings.values()), 2)
    try:
        code = int(status_line.split()[1])
    except (IndexError, ValueError):
        return CheckOutcome(False, total, "bad HTTP response", timings, cert_days)
    if code >= 400:
        return CheckOutcome(False, total, f"HTTP {code}", timings, cert_days)
    return CheckOutcome(True, total, None, timings, cert_days)
