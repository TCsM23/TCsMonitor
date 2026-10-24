"""Read-only info about THIS machine: interfaces, active connections, Wi-Fi, subnet math."""
import ipaddress
import re
import shutil
import socket
from collections import Counter

import psutil

from .checks import IS_WINDOWS
from .tools import ToolError, run_cmd


def interfaces() -> list[dict]:
    stats = psutil.net_if_stats()
    io = psutil.net_io_counters(pernic=True)
    rows = []
    for name, addrs in psutil.net_if_addrs().items():
        row = {"name": name, "ipv4": None, "netmask": None, "cidr": None, "ipv6": [], "mac": None}
        for a in addrs:
            if a.family == socket.AF_INET:
                row["ipv4"], row["netmask"] = a.address, a.netmask
                if a.netmask:
                    row["cidr"] = str(ipaddress.ip_interface(f"{a.address}/{a.netmask}").network)
            elif a.family == socket.AF_INET6:
                row["ipv6"].append(a.address.split("%")[0])
            elif a.family == psutil.AF_LINK:
                row["mac"] = a.address.replace("-", ":").lower()
        s = stats.get(name)
        row.update(up=s.isup if s else None, speed_mbps=s.speed if s else None,
                   mtu=s.mtu if s else None)
        c = io.get(name)
        row.update(bytes_sent=c.bytes_sent if c else 0, bytes_recv=c.bytes_recv if c else 0)
        rows.append(row)
    rows.sort(key=lambda r: (not r["up"], r["ipv4"] is None, r["name"]))
    return rows


_STATUS_ORDER = {"ESTABLISHED": 0, "LISTEN": 1, "TIME_WAIT": 2, "CLOSE_WAIT": 3, "SYN_SENT": 4}


def connections() -> dict:
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return {"error": "Access denied: run as administrator to list connections",
                "rows": [], "counts": {}, "total": 0}
    names: dict[int, str] = {}

    def pname(pid: int | None) -> str:
        if not pid:
            return "-"
        if pid not in names:
            try:
                names[pid] = psutil.Process(pid).name()
            except psutil.Error:
                names[pid] = "?"
        return names[pid]

    rows, counts = [], Counter()
    for c in conns:
        tcp = c.type == socket.SOCK_STREAM
        status = c.status if tcp else "UDP"
        counts[status] += 1
        rows.append({
            "proto": "TCP" if tcp else "UDP",
            "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
            "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
            "status": status, "pid": c.pid, "process": pname(c.pid),
        })
    rows.sort(key=lambda r: (_STATUS_ORDER.get(r["status"], 9), r["process"]))
    return {"rows": rows[:400], "counts": dict(counts), "total": len(rows)}


WIFI_FIELDS = ["Name", "State", "SSID", "BSSID", "Band", "Radio type", "Channel", "Signal",
               "Receive rate (Mbps)", "Transmit rate (Mbps)", "Authentication"]


async def wifi() -> dict:
    if IS_WINDOWS and shutil.which("netsh"):
        _, out = await run_cmd(["netsh", "wlan", "show", "interfaces"], 10)
        info: dict[str, str] = {}
        for line in out.splitlines():
            if ":" in line:
                key, val = line.split(":", 1)
                info.setdefault(key.strip(), val.strip())
        if "State" not in info:
            reason = out.strip().splitlines()[0] if out.strip() else "No Wi-Fi interface"
            return {"available": False, "reason": reason[:200]}
        return {"available": True, "fields": {k: info[k] for k in WIFI_FIELDS if k in info}}

    if shutil.which("nmcli"):
        _, out = await run_cmd(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,RATE,SIGNAL,SECURITY",
                                "dev", "wifi"], 10)
        for line in out.splitlines():
            parts = [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", line)]
            if parts and parts[0] == "yes" and len(parts) >= 7:
                return {"available": True, "fields": {
                    "SSID": parts[1], "BSSID": parts[2], "Channel": parts[3],
                    "Rate": parts[4], "Signal": f"{parts[5]}%", "Security": parts[6]}}
        return {"available": False, "reason": "Not connected to Wi-Fi"}
    return {"available": False, "reason": "Wi-Fi info needs netsh (Windows) or nmcli (Linux)"}


def subnet(cidr: str) -> dict:
    try:
        iface = ipaddress.ip_interface(cidr.strip())
    except ValueError as exc:
        raise ToolError(f"Not a valid address/prefix: {exc}") from exc
    net = iface.network
    out = {"input": cidr, "ip": str(iface.ip), "cidr": str(net), "prefix": net.prefixlen,
           "network": str(net.network_address), "netmask": str(net.netmask),
           "wildcard": str(net.hostmask), "total_addresses": net.num_addresses,
           "private": net.is_private, "version": net.version}
    if net.version == 4:
        small = net.prefixlen >= 31
        first = net.network_address if small else net.network_address + 1
        last = net.broadcast_address if small else net.broadcast_address - 1
        first_octet = int(str(net.network_address).split(".")[0])
        out.update(broadcast=str(net.broadcast_address), first_host=str(first),
                   last_host=str(last),
                   usable_hosts=net.num_addresses if small else net.num_addresses - 2,
                   ip_class="A" if first_octet < 128 else "B" if first_octet < 192
                   else "C" if first_octet < 224 else "D/E")
    return out
