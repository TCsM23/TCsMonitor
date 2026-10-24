"""TCsMonitor: FastAPI app, REST API, WebSocket endpoint, and background tasks."""
import asyncio
import ipaddress
import logging
import mimetypes
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import (Depends, FastAPI, HTTPException, Query, Request, Response, WebSocket,
                     WebSocketDisconnect)
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, select

from . import monitor as mon
from . import auth, netinfo, tools
from .db import engine, get_session, init_db
from .models import CheckResult, Device, Host, utcnow
from .schemas import (CheckResultRead, DeviceRead, DiscoverIn, HostCreate, HostRead,
                      HostStatus, SpeedIn, TargetIn)
from .sniffer import sniffer
from .ws import manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
STATIC = Path(__file__).parent / "static"
mimetypes.add_type("application/manifest+json", ".webmanifest")


async def packet_pump() -> None:
    """Every 0.5 s, push captured packets to dashboards in one batch (not one message each)."""
    while True:
        await asyncio.sleep(0.5)
        if sniffer.running and manager.active:
            batch = sniffer.drain()
            if batch:
                await manager.broadcast({"type": "packets", "rows": batch[-200:],
                                         "status": sniffer.status()})
        elif sniffer.running:
            sniffer.drain()  # nobody watching: don't let the queue grow


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    mon.monitor = mon.Monitor()
    mon.monitor.start()
    pump = asyncio.create_task(packet_pump())
    yield
    pump.cancel()
    sniffer.stop()
    await mon.monitor.stop()


app = FastAPI(title="TCsMonitor", version="1.1.0", lifespan=lifespan,
              docs_url=None if auth.enabled() else "/docs", redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


# ---- login -------------------------------------------------------------------
@app.middleware("http")
async def require_login(request: Request, call_next):
    """Every page and API call needs a valid session cookie (static files and /login don't)."""
    path = request.url.path
    if path in ("/login", "/sw.js") or path.startswith("/static/") \
            or auth.valid_token(request.cookies.get(auth.COOKIE)):
        return await call_next(request)
    if path.startswith("/api/"):
        return JSONResponse({"detail": "Not logged in"}, status_code=401)
    return RedirectResponse("/login")


_failed: list[float] = []


@app.get("/login", include_in_schema=False)
def login_page():
    if not auth.enabled():
        return RedirectResponse("/")
    return FileResponse(STATIC / "login.html", headers={"Cache-Control": "no-cache"})


@app.post("/login", include_in_schema=False)
async def login(request: Request):
    now = asyncio.get_running_loop().time()
    _failed[:] = [t for t in _failed if now - t < 600]
    if len(_failed) >= 10:  # 10 wrong tries in 10 minutes -> wait
        raise HTTPException(429, "Too many attempts, try again in a few minutes")
    body = await request.json()
    if not auth.check_password(str(body.get("password", ""))):
        _failed.append(now)
        await asyncio.sleep(1)  # slows down password guessing
        raise HTTPException(401, "Wrong password")
    resp = Response(status_code=204)
    resp.set_cookie(auth.COOKIE, auth.make_token(), max_age=auth.MAX_AGE, httponly=True,
                    samesite="lax", secure=request.url.scheme == "https")
    return resp


@app.post("/logout", include_in_schema=False)
def logout():
    resp = Response(status_code=204)
    resp.delete_cookie(auth.COOKIE)
    return resp


def tool_call(exc: tools.ToolError) -> HTTPException:
    return HTTPException(400, str(exc))


# ---- pages -------------------------------------------------------------------
@app.get("/sw.js", include_in_schema=False)
def service_worker() -> FileResponse:
    """Served from the root so its scope covers the whole app (a worker under /static/
    could only control /static/...). no-cache so phones always check for a new version."""
    return FileResponse(STATIC / "sw.js", media_type="application/javascript",
                        headers={"Cache-Control": "no-cache"})

@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    # no-cache: if the server is unreachable the browser must not show a stale copy;
    # the service worker shows offline.html instead.
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})


# ---- hosts -------------------------------------------------------------------
def to_status(host: Host, session: Session) -> HostStatus:
    st = mon.monitor.state(host.id)
    last = st.last
    return HostStatus(
        **HostRead.model_validate(host, from_attributes=True).model_dump(),
        status=st.status,
        last_latency_ms=last.latency_ms if last else None,
        last_checked=st.last_checked,
        last_error=last.error if last else None,
        uptime_24h=mon.uptime_percent(session, host.id),
        loss_pct=st.loss_pct, jitter_ms=st.jitter_ms,
        cert_days=last.cert_days if last else None,
        timings=last.timings if last else {},
    )


@app.get("/api/hosts", response_model=list[HostStatus])
def list_hosts(session: Session = Depends(get_session)):
    return [to_status(h, session) for h in session.exec(select(Host).order_by(Host.id))]


@app.post("/api/hosts", response_model=HostStatus, status_code=201)
def add_host(data: HostCreate, session: Session = Depends(get_session)):
    host = Host(**data.model_dump())
    session.add(host)
    session.commit()
    session.refresh(host)
    mon.monitor.check_now()
    return to_status(host, session)


@app.patch("/api/hosts/{host_id}/toggle", response_model=HostStatus)
def toggle_host(host_id: int, session: Session = Depends(get_session)):
    host = session.get(Host, host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    host.enabled = not host.enabled
    session.add(host)
    session.commit()
    session.refresh(host)
    if not host.enabled:
        mon.monitor.states.pop(host.id, None)
    return to_status(host, session)


@app.delete("/api/hosts/{host_id}", status_code=204)
def delete_host(host_id: int, session: Session = Depends(get_session)):
    host = session.get(Host, host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    for r in session.exec(select(CheckResult).where(CheckResult.host_id == host_id)):
        session.delete(r)
    session.delete(host)
    session.commit()
    mon.monitor.states.pop(host_id, None)


@app.get("/api/hosts/{host_id}/history", response_model=list[CheckResultRead])
def history(host_id: int, limit: int = Query(60, ge=1, le=1000),
            session: Session = Depends(get_session)):
    if not session.get(Host, host_id):
        raise HTTPException(404, "Host not found")
    rows = session.exec(select(CheckResult).where(CheckResult.host_id == host_id)
                        .order_by(CheckResult.timestamp.desc()).limit(limit)).all()
    return list(reversed(rows))


@app.get("/api/events")
def events():
    return mon.monitor.events


@app.get("/api/system")
def system():
    return mon.monitor.system_stats()


@app.post("/api/check-now", status_code=202)
def check_now():
    mon.monitor.check_now()
    return {"ok": True}


# ---- this machine ------------------------------------------------------------
@app.get("/api/net/interfaces")
def net_interfaces():
    return netinfo.interfaces()


@app.get("/api/net/connections")
async def net_connections():
    return await asyncio.to_thread(netinfo.connections)


@app.get("/api/net/wifi")
async def net_wifi():
    try:
        return await netinfo.wifi()
    except tools.ToolError as exc:
        return {"available": False, "reason": str(exc)}


# ---- tools -------------------------------------------------------------------
@app.get("/api/tools/subnet")
def tool_subnet(cidr: str = Query(..., min_length=1, max_length=50)):
    try:
        return netinfo.subnet(cidr)
    except tools.ToolError as exc:
        raise tool_call(exc)


@app.post("/api/tools/traceroute")
async def tool_traceroute(data: TargetIn):
    try:
        return await tools.traceroute(data.host)
    except tools.ToolError as exc:
        raise tool_call(exc)


@app.post("/api/tools/mtu")
async def tool_mtu(data: TargetIn):
    try:
        return await tools.mtu_check(data.host)
    except tools.ToolError as exc:
        raise tool_call(exc)


@app.post("/api/tools/speedtest")
async def tool_speed(data: SpeedIn):
    try:
        return await tools.speed_test(data.url or tools.DEFAULT_SPEED_URL)
    except tools.ToolError as exc:
        raise tool_call(exc)


# ---- LAN ---------------------------------------------------------------------
@app.get("/api/lan/networks")
def lan_networks():
    return tools.lan_candidates()


def _merge_devices(found: list[dict]) -> list[dict]:
    """Upsert devices by MAC. Returns the ones never seen before (empty on the first scan)."""
    now, new = utcnow(), []
    with Session(engine) as s:
        baseline = s.exec(select(Device)).first() is None  # first scan = trusted baseline
        for d in found:
            if not d["mac"]:
                continue
            dev = s.get(Device, d["mac"])
            if dev is None:
                s.add(Device(mac=d["mac"], ip=d["ip"], vendor=d["vendor"], known=baseline))
                if not baseline:
                    new.append(d)
            else:
                dev.ip, dev.last_seen = d["ip"], now
                dev.vendor = d["vendor"] or dev.vendor
                s.add(dev)
        s.commit()
    return new


@app.post("/api/lan/discover")
async def lan_discover(data: DiscoverIn):
    try:
        result = await tools.discover(data.cidr)
    except tools.ToolError as exc:
        raise tool_call(exc)
    new = await asyncio.to_thread(_merge_devices, result["devices"])
    for d in new:
        await mon.monitor.emit("device", d["ip"],
                               f"New device on LAN: {d['ip']} ({d['mac']}, "
                               f"{d['vendor'] or 'unknown vendor'})", "warning")
    result["new"] = [d["mac"] for d in new]
    return result


@app.get("/api/lan/devices", response_model=list[DeviceRead])
def lan_devices(session: Session = Depends(get_session)):
    devs = session.exec(select(Device)).all()
    return sorted(devs, key=lambda d: ipaddress.ip_address(d.ip))


@app.patch("/api/lan/devices/{mac}/known", response_model=DeviceRead)
def lan_toggle_known(mac: str, session: Session = Depends(get_session)):
    dev = session.get(Device, mac.lower())
    if not dev:
        raise HTTPException(404, "Device not found")
    dev.known = not dev.known
    session.add(dev)
    session.commit()
    session.refresh(dev)
    return dev


# ---- packet log --------------------------------------------------------------
@app.get("/api/packets/status")
def packets_status():
    return sniffer.status()


@app.post("/api/packets/start")
async def packets_start():
    await asyncio.to_thread(sniffer.start)
    return sniffer.status()


@app.post("/api/packets/stop")
def packets_stop():
    sniffer.stop()
    return sniffer.status()


@app.get("/api/packets/recent")
def packets_recent():
    return list(sniffer.recent)[-300:]


# ---- live updates ------------------------------------------------------------
@app.websocket("/ws")
async def websocket(ws: WebSocket):
    if not auth.valid_token(ws.cookies.get(auth.COOKIE)):  # middleware doesn't cover WebSockets
        await ws.close(code=1008)
        return
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)
