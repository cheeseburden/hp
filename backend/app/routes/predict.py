"""
routes/predict.py — Prediction endpoints for single and batch event inference.
"""

from fastapi import APIRouter, HTTPException
from typing import List
from app.schemas import NetworkEvent, PredictionResult, BatchPredictRequest
from app.threat_engine import process_event
from app import kafka_client

router = APIRouter(prefix="/api", tags=["prediction"])


@router.post("/predict", response_model=PredictionResult)
async def predict_event(event: NetworkEvent):
    """
    Process a single network event through the full pipeline.
    Returns prediction result with all pipeline stage details.
    """
    try:
        result = process_event(event)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")


@router.post("/ingest")
async def ingest_event(event: NetworkEvent):
    """
    Async ingestion — produces to Kafka.
    Result will be broadcast via WebSocket when the consumer processes it.
    """
    success = kafka_client.produce_raw_event(event.model_dump())
    kafka_client.flush()
    return {"status": "queued" if success else "kafka_unavailable"}



@router.post("/batch", response_model=List[PredictionResult])
async def batch_predict(request: BatchPredictRequest):
    """
    Process multiple network events through the pipeline.
    """
    if len(request.events) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 events per batch")

    results = []
    for event in request.events:
        try:
            result = process_event(event)
            results.append(result)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Batch prediction error: {str(e)}")

    return results
