"""WebSocket connection manager: keeps track of open dashboards and broadcasts to them."""
from typing import Any

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self.active: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.active.discard(ws)

    async def broadcast(self, message: dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:  # closed tab, network drop...
                dead.append(ws)
        for ws in dead:  # one dead socket must not break the broadcast for everyone
            self.disconnect(ws)


manager = ConnectionManager()
