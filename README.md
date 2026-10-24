# TCsMonitor

Retro-terminal network monitor built with FastAPI. Only monitor and scan devices you own.

## Run it on your PC (development)

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000. With no `TCSM_PASSWORD` set, login is off and API docs are at `/docs`.
Only 4 dependencies: fastapi, uvicorn, sqlmodel, psutil. The packet log uses Python's built-in
raw sockets (no scapy, no Npcap) but needs Administrator (Windows) or root / CAP_NET_RAW (Linux).

MAC vendor names (optional): download https://standards-oui.ieee.org/oui/oui.txt into `data/oui.txt`.

## Run it at home 24/7 (production)

| Setting | Meaning |
|---|---|
| `TCSM_PASSWORD` | Turns on the login page (and hides `/docs`). Always set this when it runs 24/7. |
| `TCSM_PORT` | The port you run on; the packet log hides this port's own traffic |
| `TCSM_INTERVAL` | Seconds between check rounds (default 10) |

Always run with `--workers 1`: the monitor loop and packet capture live inside the process.

**Windows PC**
1. Edit `deploy/start-tcsmonitor.bat` and change `TCSM_PASSWORD`.
2. Task Scheduler → Create Task → Trigger: *At startup* → Action: run the .bat file.
   Tick *Run whether user is logged on or not* and *Run with highest privileges* (needed for the packet log).
3. Power options → Sleep: *Never* (a sleeping PC monitors nothing).
4. Logs go to `data/server.log`.

**Raspberry Pi / Linux**
1. Copy the project to `/home/pi/tcsmonitor`, create the venv, `pip install -r requirements.txt`.
2. Edit `deploy/tcsmonitor.service` (user, paths, password), then:
   `sudo cp deploy/tcsmonitor.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now tcsmonitor`
3. Logs: `journalctl -u tcsmonitor -f`. The service grants CAP_NET_RAW so capture works without root.

**Access from anywhere: Tailscale**
1. Install Tailscale on the server and on your phone/laptop; sign in with the same account.
2. Open `http://<server-tailscale-name>:8000` from any of your devices, even on mobile data.
3. Don't port-forward 8000 on your router; Tailscale makes that unnecessary.

## Install it as an app (PWA)

Phones only offer "Install" over **HTTPS**. Tailscale gives you that for free:

1. On the PC: `tailscale serve --bg 8000` (if your version complains, check `tailscale serve --help`).
   It prints an address like `https://<pc-name>.<your-tailnet>.ts.net`.
2. **Android (Chrome):** open that address → tap the **install** button in TCsMonitor's top bar,
   or ⋮ menu → *Install app*.
3. **iPhone (Safari):** open the address → Share → *Add to Home Screen*.
4. **PC (Chrome/Edge):** the install icon in the address bar, or the **install** button.

The app opens full-screen with its own icon. Monitoring data is always live (never cached);
only the page shell is cached, so if the PC is off you get an "unreachable" screen with a Retry button.
After changing files in `app/static/`, bump `VERSION` in `app/static/sw.js` so installed apps update.

## Pages

| Page | What it does | Networking concept |
|---|---|---|
| Monitor | Ping/TCP/HTTP checks, latency chart, loss %, jitter, 24h uptime, cert expiry, live log | ICMP, TCP handshake, QoS |
| Monitor (HTTP host) | Timing bar: DNS, TCP connect, TLS handshake, first byte | DNS, TLS |
| Packets | Live capture of this machine's traffic (Windows: IPv4 only), filters and breakdown | OSI layers, TCP flags, ARP, DNS |
| LAN | Ping sweep + ARP table, vendor lookup, new-device alerts, trust list | Subnetting, ARP, MAC/OUI |
| Tools | Traceroute with latency-jump highlight, subnet calculator, MTU check, speed test, Wi-Fi info | TTL/routing, CIDR, MTU, throughput |
| System | Interfaces (IP, mask, MAC, MTU, speed) and active connections by process | Addressing, sockets, TCP states |

## Files

| File | Job |
|---|---|
| `app/checks.py` | ping / TCP / hand-written HTTP check with per-stage timing and cert days |
| `app/monitor.py` | Background loop, hysteresis (3 fails = down), loss/jitter over last 20 checks, events |
| `app/tools.py` | Discovery + ARP, OUI lookup, traceroute, MTU binary search, speed test |
| `app/netinfo.py` | Interfaces, connections, Wi-Fi (netsh/nmcli), subnet math |
| `app/sniffer.py` | Raw-socket capture thread, hand-parsed Ethernet/ARP/IP/TCP/UDP/DNS/ICMP headers |
| `app/main.py` | Routes, login middleware, lifespan, packet pump, device merging |
| `app/auth.py` | Password check and signed session cookie (stdlib hmac) |
| `deploy/` | Windows Task Scheduler script and Linux systemd service |
| `app/static/` | `index.html`, `style.css`, `app.js` (vanilla JS), bundled Chart.js |
| `app/static/sw.js`, `manifest.webmanifest`, `offline.html`, `icons/` | PWA: service worker, app manifest, offline screen, app icons |

## Notes

- The first LAN scan is the trusted baseline; devices that appear in later scans raise an alert.
- "Randomized (private) MAC" = phones hiding their real MAC (locally administered bit set).
- Router admin pages over HTTPS with self-signed certs fail the HTTP check with a TLS error; use a TCP check on 443.
- Discovery only accepts private ranges of /22 or smaller; tool inputs reject anything that isn't an IP/hostname.
- The ✕ on each window collapses it.
