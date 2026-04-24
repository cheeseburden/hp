"""
ws_manager.py — Manages WebSocket connections and broadcasts pipeline results.
"""
import asyncio
import logging
from typing import Set
from fastapi import WebSocket

logger = logging.getLogger("hpe.ws_manager")

class ConnectionManager:
    """Manages active WebSocket connections and broadcasts results."""
    
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
    
    def add(self, websocket: WebSocket):
        self.active_connections.add(websocket)
        logger.info(f"WebSocket added. Active: {len(self.active_connections)}")
    
    def remove(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info(f"WebSocket removed. Active: {len(self.active_connections)}")
    
    async def broadcast(self, message: dict):
        """Send a message to all connected clients."""
        dead = set()
        for ws in self.active_connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.add(ws)
        
        for ws in dead:
            self.active_connections.discard(ws)


# Singleton instance
manager = ConnectionManager()
