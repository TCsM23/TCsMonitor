"""On-demand network tools: LAN discovery + ARP, traceroute, MTU check, speed test.

Discovery is limited to private (LAN) ranges of /22 or smaller: only scan networks you own.
"""
import asyncio
import ipaddress
import re
import shutil
import socket
import ssl
import time
from pathlib import Path
from urllib.parse import urlsplit

import psutil

from .checks import IS_WINDOWS, ping_host

IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
MAC = r"[0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5}"
OUI_FILE = Path(__file__).resolve().parent.parent / "data" / "oui.txt"
DEFAULT_SPEED_URL = "https://speed.cloudflare.com/__down?bytes=25000000"


class ToolError(Exception):
    """A tool failed in a way the user should see (bad input, missing command...)."""


async def run_cmd(args: list[str], timeout: float) -> tuple[int, str]:
    if shutil.which(args[0]) is None:
        raise ToolError(f"'{args[0]}' command not found on this machine")
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise ToolError(f"{args[0]} took longer than {timeout:.0f}s") from None
    return proc.returncode or 0, out.decode(errors="ignore")


# ---- LAN discovery ---------------------------------------------------------
def lan_candidates() -> list[str]:
    """Private IPv4 networks this machine is on (Wi-Fi, Ethernet, virtual adapters)."""
    found: list[str] = []
    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        if name in stats and not stats[name].isup:
            continue
        for a in addrs:
            if a.family != socket.AF_INET or not a.netmask:
                continue
            iface = ipaddress.ip_interface(f"{a.address}/{a.netmask}")
            if iface.ip.is_loopback or iface.ip.is_link_local or not iface.ip.is_private:
                continue
            net = iface.network if iface.network.prefixlen >= 22 \
                else ipaddress.ip_interface(f"{a.address}/24").network
            if str(net) not in found:
                found.append(str(net))
    return found


def _norm_mac(mac: str) -> str:
    return mac.lower().replace("-", ":")


async def read_arp_table() -> dict[str, str]:
    """IP -> MAC from the OS ARP cache (filled in by the ping sweep)."""
    if not IS_WINDOWS and Path("/proc/net/arp").exists():
        out = Path("/proc/net/arp").read_text()
    else:
        _, out = await run_cmd(["arp", "-a"] if IS_WINDOWS else ["arp", "-an"], 10)
    table = {}
    for m in re.finditer(rf"({IPV4})[^\n]*?({MAC})", out):
        mac = _norm_mac(m.group(2))
        first = int(mac[:2], 16)
        if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") or first & 1:  # broadcast/multicast
            continue
        table[m.group(1)] = mac
    return table


_oui: dict[str, str] | None = None


def vendor_for(mac: str) -> str | None:
    """OUI = first 3 bytes of a MAC. Needs data/oui.txt from the IEEE (see README)."""
    global _oui
    if int(mac[:2], 16) & 2:  # "locally administered" bit: phones randomize MACs for privacy
        return "Randomized (private) MAC"
    if _oui is None:
        _oui = {}
        if OUI_FILE.exists():
            for line in OUI_FILE.read_text(errors="ignore").splitlines():
                m = re.match(r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$", line)
                if m:
                    _oui[m.group(1).replace("-", ":").lower()] = m.group(2).strip()
    return _oui.get(mac[:8])


async def discover(cidr: str) -> dict:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ToolError(f"Not a valid network: {exc}") from exc
    if net.version != 4 or not net.is_private:
        raise ToolError("Only private IPv4 (LAN) ranges can be scanned")
    if net.num_addresses > 1024:
        raise ToolError("Range too large: use /22 or smaller")

    start = time.perf_counter()
    sem = asyncio.Semaphore(64)  # don't fire 254 ping processes at once

    async def probe(ip: str) -> tuple[str, float | None]:
        async with sem:
            r = await ping_host(ip, timeout=1)
            return ip, r.latency_ms if r.success else None

    results = await asyncio.gather(*(probe(str(ip)) for ip in net.hosts()))
    replied = {ip: lat for ip, lat in results if lat is not None}
    arp = await read_arp_table()

    devices = []
    for ip in sorted(set(replied) | {i for i in arp if ipaddress.ip_address(i) in net},
                     key=lambda i: ipaddress.ip_address(i)):
        mac = arp.get(ip)
        devices.append({"ip": ip, "mac": mac, "vendor": vendor_for(mac) if mac else None,
                        "latency_ms": replied.get(ip), "ping": ip in replied})
    return {"cidr": str(net), "seconds": round(time.perf_counter() - start, 1),
            "devices": devices, "oui_loaded": bool(_oui)}


# ---- traceroute -------------------------------------------------------------
async def traceroute(host: str, max_hops: int = 20) -> dict:
    if IS_WINDOWS:
        args = ["tracert", "-d", "-w", "1000", "-h", str(max_hops), host]
    else:
        args = ["traceroute", "-n", "-w", "1", "-q", "3", "-m", str(max_hops), host]
    _, out = await run_cmd(args, 90)
    hops, prev = [], None
    for line in out.splitlines():
        m = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if not m:
            continue
        rest = m.group(2)
        times = [float(t.lstrip("<")) for t in re.findall(r"(<?[\d.]+)\s*ms", rest)]
        ip = re.search(IPV4, rest)
        avg = round(sum(times) / len(times), 1) if times else None
        jump = round(avg - prev, 1) if avg is not None and prev is not None else None
        hops.append({"hop": int(m.group(1)), "ip": ip.group(0) if ip else None,
                     "times": times, "avg": avg, "jump": jump, "timeout": not times})
        if avg is not None:
            prev = avg
    if not hops:
        raise ToolError(out.strip().splitlines()[0][:200] if out.strip() else "No output")
    return {"host": host, "hops": hops}


# ---- MTU check ----------------------------------------------------------------
async def _df_ping(host: str, size: int) -> bool:
    """Ping with the don't-fragment bit: fails if the packet is bigger than the path MTU."""
    if IS_WINDOWS:
        args = ["ping", "-f", "-l", str(size), "-n", "1", "-w", "1000", host]
    else:
        args = ["ping", "-M", "do", "-s", str(size), "-c", "1", "-W", "1", host]
    code, out = await run_cmd(args, 5)
    return code == 0 and "ttl=" in out.lower()


async def mtu_check(host: str) -> dict:
    steps = []
    if not await _df_ping(host, 32):
        raise ToolError("Host did not reply to ping")
    if await _df_ping(host, 1472):
        steps.append({"size": 1472, "ok": True})
        return {"host": host, "payload": 1472, "mtu": 1500, "steps": steps}
    steps.append({"size": 1472, "ok": False})
    lo, hi = 32, 1472  # lo fits, hi doesn't: binary search the boundary
    while hi - lo > 1:
        mid = (lo + hi) // 2
        ok = await _df_ping(host, mid)
        steps.append({"size": mid, "ok": ok})
        lo, hi = (mid, hi) if ok else (lo, mid)
    return {"host": host, "payload": lo, "mtu": lo + 28, "steps": steps}  # +20 IP +8 ICMP


# ---- speed test ---------------------------------------------------------------
async def speed_test(url: str = DEFAULT_SPEED_URL, max_seconds: float = 15) -> dict:
    """Download over a plain asyncio stream (no httpx) and measure throughput.
    HTTP/1.0 is used on purpose: the server can't use chunked encoding, it just streams
    the body and closes, so every byte read is file data."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ToolError("URL must start with http:// or https://")
    https = parts.scheme == "https"
    port = parts.port or (443 if https else 80)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    tls = {"ssl": ssl.create_default_context(), "server_hostname": parts.hostname} if https else {}

    writer = None
    total = 0
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(parts.hostname, port, **tls), 10)
        writer.write(f"GET {path} HTTP/1.0\r\nHost: {parts.hostname}\r\n"
                     "User-Agent: TCsMonitor/1.0\r\n\r\n".encode())
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
        ttfb = round((time.perf_counter() - start) * 1000, 1)
        code = int(head.split(b" ", 2)[1])
        if code >= 300:
            raise ToolError(f"Server answered HTTP {code}")
        first = time.perf_counter()
        while time.perf_counter() - start < max_seconds:
            chunk = await asyncio.wait_for(reader.read(65536), 10)
            if not chunk:
                break
            total += len(chunk)
    except (OSError, ssl.SSLError, asyncio.TimeoutError, asyncio.IncompleteReadError,
            asyncio.LimitOverrunError, ValueError, IndexError) as exc:
        raise ToolError(f"Download failed: {type(exc).__name__}") from exc
    finally:
        if writer is not None:
            writer.close()
    elapsed = max(time.perf_counter() - first, 1e-6)
    return {"url": url, "bytes": total, "seconds": round(elapsed, 2), "ttfb_ms": ttfb,
            "mbps": round(total * 8 / elapsed / 1e6, 2)}
