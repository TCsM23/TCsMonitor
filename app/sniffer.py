"""Wireshark-style packet log using only Python's standard library (raw sockets).

Linux:   AF_PACKET socket sees every Ethernet frame, including ARP.
         Needs root, or the CAP_NET_RAW capability (the systemd service grants it).
Windows: raw IP socket + SIO_RCVALL sees IPv4 packets (no ARP, no IPv6).
         Needs "Run as administrator". No Npcap or scapy required.

Headers are parsed by hand with struct, the same layouts you learn in NET 102.
Capture runs in its own thread; summaries are batched and pushed over the WebSocket.
"""
import os
import platform
import socket
import struct
import threading
import time
from collections import Counter, deque

SYSTEM = platform.system()
IGNORE_PORT = int(os.getenv("TCSM_PORT", "8000"))  # skip the dashboard's own traffic

ICMP_TYPES = {0: "Echo reply", 3: "Destination unreachable", 8: "Echo request (ping)",
              11: "Time exceeded (TTL hit 0)"}
ICMP6_TYPES = {128: "Echo request", 129: "Echo reply", 133: "Router solicitation",
               134: "Router advertisement", 135: "Neighbor solicitation (IPv6 ARP)",
               136: "Neighbor advertisement"}
TCP_FLAGS = [(0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"), (0x01, "FIN"), (0x04, "RST"),
             (0x20, "URG")]
UDP_NAMES = {67: "DHCP", 68: "DHCP", 123: "NTP", 1900: "SSDP", 5353: "mDNS"}


def local_ip() -> str:
    """The IPv4 address of the interface with the default route.
    Connecting a UDP socket sends no packets; it just asks the OS which route it would use."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        return s.getsockname()[0]
    finally:
        s.close()


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _dns_name(b: bytes, i: int) -> str:
    labels = []
    for _ in range(64):
        if i >= len(b) or b[i] == 0 or b[i] & 0xC0:  # end, or a compression pointer
            break
        n = b[i]
        labels.append(b[i + 1:i + 1 + n].decode(errors="ignore"))
        i += 1 + n
    return ".".join(labels) or "?"


class PacketSniffer:
    def __init__(self) -> None:
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.error: str | None = None
        self.recent: deque = deque(maxlen=500)
        self.counts: Counter = Counter()
        self.total_bytes = 0
        self._pending: list[dict] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._layer = "eth"

    @property
    def running(self) -> bool:
        return bool(self.thread and self.thread.is_alive() and not self._stop.is_set())

    def status(self) -> dict:
        note = "IPv4 only on Windows (no ARP)" if SYSTEM == "Windows" else None
        return {"running": self.running, "error": self.error, "note": note,
                "counts": dict(self.counts), "total_bytes": self.total_bytes}

    # ---- start / stop ------------------------------------------------------
    def start(self) -> None:
        if self.running:
            return
        self.error = None
        self._stop.clear()
        try:
            self.sock = self._open()
        except PermissionError:
            self.error = ("Permission denied: run as Administrator (Windows) "
                          "or root / CAP_NET_RAW (Linux)")
            return
        except (OSError, AttributeError, ValueError) as exc:
            self.error = f"Packet capture not available here: {exc}"
            return
        self.thread = threading.Thread(target=self._loop, daemon=True, name="packet-capture")
        self.thread.start()

    def _open(self) -> socket.socket:
        if SYSTEM == "Linux":
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))  # ETH_P_ALL
            self._layer = "eth"
        elif SYSTEM == "Windows":
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((local_ip(), 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # promiscuous for this interface
            self._layer = "ip"
        else:
            raise OSError(f"raw capture isn't supported on {SYSTEM}")
        s.settimeout(1.0)  # so the loop can notice stop() within a second
        return s

    def stop(self) -> None:
        self._stop.set()
        if self.thread:
            self.thread.join(timeout=2)
        if self.sock:
            if SYSTEM == "Windows":
                try:
                    self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except OSError:
                    pass
            self.sock.close()
        self.sock = self.thread = None

    def drain(self) -> list[dict]:
        with self._lock:
            batch, self._pending = self._pending, []
        return batch

    # ---- capture thread ----------------------------------------------------
    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                self.error = f"Capture stopped: {exc}"
                break
            if self._layer == "eth" and addr and addr[0] == "lo":
                continue  # loopback shows every packet twice; skip it
            try:
                row = self._parse(data)
            except (struct.error, IndexError, OSError, ValueError):
                continue  # truncated or odd packet: never kill the thread
            if row:
                with self._lock:
                    self._pending.append(row)
                    self.recent.append(row)
                    self.counts[row["proto"]] += 1
                    self.total_bytes += row["len"]

    # ---- parsing (layer by layer) ------------------------------------------
    @staticmethod
    def _row(proto: str, length: int, src: str = "", dst: str = "", info: str = "") -> dict:
        return {"t": time.time(), "src": src, "dst": dst, "proto": proto,
                "len": length, "info": info}

    def _parse(self, data: bytes) -> dict | None:
        if self._layer == "ip":
            return self._ipv4(data, len(data))
        # Ethernet II: 6 bytes dst MAC, 6 bytes src MAC, 2 bytes EtherType
        ethertype = struct.unpack("!H", data[12:14])[0]
        payload = data[14:]
        if ethertype == 0x0806:
            return self._arp(payload, len(data))
        if ethertype == 0x0800:
            return self._ipv4(payload, len(data))
        if ethertype == 0x86DD:
            return self._ipv6(payload, len(data))
        return self._row("OTHER", len(data), _mac(data[6:12]), _mac(data[0:6]),
                         f"EtherType 0x{ethertype:04x}")

    def _arp(self, p: bytes, length: int) -> dict:
        op = struct.unpack("!H", p[6:8])[0]
        sender_mac, sender_ip = _mac(p[8:14]), socket.inet_ntoa(p[14:18])
        target_ip = socket.inet_ntoa(p[24:28])
        info = (f"Who has {target_ip}? Tell {sender_ip}" if op == 1
                else f"{sender_ip} is at {sender_mac}")
        return self._row("ARP", length, sender_ip, target_ip, info)

    def _ipv4(self, p: bytes, length: int) -> dict | None:
        ihl = (p[0] & 0x0F) * 4          # header length in 32-bit words
        proto, ttl = p[9], p[8]
        src, dst = socket.inet_ntoa(p[12:16]), socket.inet_ntoa(p[16:20])
        return self._transport(proto, p[ihl:], src, dst, length, ttl)

    def _ipv6(self, p: bytes, length: int) -> dict | None:
        src = socket.inet_ntop(socket.AF_INET6, p[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, p[24:40])
        return self._transport(p[6], p[40:], src, dst, length, p[7])

    def _transport(self, proto: int, seg: bytes, src: str, dst: str, length: int,
                   ttl: int) -> dict | None:
        if proto == 6:  # TCP
            sport, dport, seq, _ack, off_flags = struct.unpack("!HHIIH", seg[:14])
            if IGNORE_PORT in (sport, dport):
                return None
            flags = ",".join(name for bit, name in TCP_FLAGS if off_flags & bit)
            name = "TLS" if 443 in (sport, dport) else "HTTP" if 80 in (sport, dport) else "TCP"
            return self._row(name, length, src, dst, f"{sport} → {dport} [{flags}] seq={seq}")
        if proto == 17:  # UDP
            sport, dport = struct.unpack("!HH", seg[:4])
            body = seg[8:]
            if 53 in (sport, dport) or 5353 in (sport, dport):
                flags = struct.unpack("!H", body[2:4])[0]
                qname = _dns_name(body, 12) if struct.unpack("!H", body[4:6])[0] else "?"
                kind = "Response" if flags & 0x8000 else "Query"
                return self._row("DNS", length, src, dst, f"{kind} {qname}")
            name = next((UDP_NAMES[p] for p in (sport, dport) if p in UDP_NAMES), "UDP")
            return self._row(name, length, src, dst, f"{sport} → {dport}")
        if proto == 1:  # ICMP
            return self._row("ICMP", length, src, dst,
                             f"{ICMP_TYPES.get(seg[0], f'type {seg[0]}')} ttl={ttl}")
        if proto == 58:  # ICMPv6
            return self._row("ICMP", length, src, dst, ICMP6_TYPES.get(seg[0], f"ICMPv6 type {seg[0]}"))
        if proto == 2:
            return self._row("OTHER", length, src, dst, "IGMP (multicast group)")
        return self._row("OTHER", length, src, dst, f"IP protocol {proto}")


sniffer = PacketSniffer()
