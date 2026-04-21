"""
routes/simulate.py — WebSocket simulation endpoint.
Streams real events from the sample dataset through the full pipeline.
"""

import json
import asyncio
import random
import logging
from pathlib import Path
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.config import SAMPLE_EVENTS_PATH
from app.schemas import NetworkEvent
from app.threat_engine import process_event

logger = logging.getLogger("hpe.simulate")
router = APIRouter(tags=["simulation"])

# Load sample events at module level
_sample_events = None


def _load_sample_events():
    """Load sample events from the exported JSON file."""
    global _sample_events
    try:
        with open(SAMPLE_EVENTS_PATH, "r", encoding="utf-8") as f:
            _sample_events = json.load(f)
        logger.info(f"Loaded {len(_sample_events.get('normal', []))} normal + "
                     f"{len(_sample_events.get('attack', []))} attack sample events")
    except Exception as e:
        logger.error(f"Failed to load sample events: {e}")
        _sample_events = {"normal": [], "attack": []}


@router.websocket("/ws/simulate")
async def simulate_stream(websocket: WebSocket):
    """
    WebSocket endpoint that simulates live events flowing through the pipeline.
    Streams real events from the two-day sample dataset.
    """
    await websocket.accept()

    if _sample_events is None:
        _load_sample_events()

    normal_events = _sample_events.get("normal", [])
    attack_events = _sample_events.get("attack", [])
    server_info = _sample_events.get("server", {"lat": 12.97, "lng": 77.59, "city": "Bangalore"})

    if not normal_events:
        await websocket.send_json({"error": "No sample events loaded"})
        await websocket.close()
        return

    # Send server info first
    await websocket.send_json({
        "type": "server_info",
        "data": server_info,
    })

    event_index = 0
    attack_index = 0

    try:
        while True:
            # Randomly decide: 92% normal, 8% attack (realistic ratio)
            is_attack_event = random.random() < 0.08 and attack_events

            if is_attack_event:
                raw_event = attack_events[attack_index % len(attack_events)]
                attack_index += 1
            else:
                raw_event = normal_events[event_index % len(normal_events)]
                event_index += 1

            # Convert to NetworkEvent and process through pipeline
            try:
                event = NetworkEvent(**{k: v for k, v in raw_event.items()
                                       if k in NetworkEvent.model_fields})
                result = process_event(event)

                # Send the full result
                await websocket.send_json({
                    "type": "pipeline_result",
                    "data": {
                        "event": raw_event,
                        "prediction": result.model_dump(),
                    }
                })

            except Exception as e:
                logger.error(f"Simulation event error: {e}")
                await websocket.send_json({
                    "type": "error",
                    "data": {"message": str(e)},
                })

            # Random delay between events (500ms - 3s)
            delay = random.uniform(0.5, 3.0)
            await asyncio.sleep(delay)

    except WebSocketDisconnect:
        logger.info("WebSocket simulation client disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")


@router.get("/api/sample-events")
async def get_sample_events():
    """Get the loaded sample events (for frontend initialization)."""
    if _sample_events is None:
        _load_sample_events()

    return {
        "normal_count": len(_sample_events.get("normal", [])),
        "attack_count": len(_sample_events.get("attack", [])),
        "server": _sample_events.get("server", {}),
        "sample_normal": _sample_events.get("normal", [])[:5],
        "sample_attack": _sample_events.get("attack", [])[:3],
    }
