import json
import logging
from typing import List
from fastapi import WebSocket
from models.schemas import SecurityEvent

logger = logging.getLogger("nyxvault.event_bus")
logging.basicConfig(level=logging.INFO)

class EventBus:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, event: SecurityEvent):
        """
        Broadcasts an event as JSON to all active WebSocket connections.
        """
        event_json = event.model_dump_json()
        logger.info(f"Broadcasting event: {event.event_type} - {event.title}")
        
        # We make a copy of connections to avoid modification issues during iteration
        for connection in list(self.active_connections):
            try:
                await connection.send_text(event_json)
            except Exception as e:
                logger.error(f"Error broadcasting to WebSocket connection: {e}")
                self.disconnect(connection)

# Global event bus instance
event_bus = EventBus()
