from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from services.detector import detection_engine
from services.event_bus import event_bus
from services.neo4j_client import neo4j_client
from models.schemas import SecurityEvent
import logging
import uuid
import asyncio
from datetime import datetime

logger = logging.getLogger("nyxvault.api.honeytokens")
router = APIRouter(tags=["Honeytoken Endpoints"])

# Helper function to trigger honeytoken detection background worker
def trigger_honeytoken_alert(path: str, method: str, client_ip: str, headers: dict):
    # Construct simulated event data matching a honeytoken API endpoint access
    event_data = {
        "is_honeytoken": True,
        "accessed_asset": path,
        "asset_type": "APIEndpoint",
        "username": headers.get("x-user-id", headers.get("authorization", "anonymous-recon")),
        "access_frequency": 1.0,
        "amount": 0.0,
        "avg_balance": 0.0,
        "unauthorized": True,
        "source_ip": client_ip,
        "details": {
            "headers_captured": {k: v for k, v in headers.items() if k.lower() in ["user-agent", "accept", "authorization", "x-forwarded-for"]}
        }
    }
    
    # Process through detection engine
    processed_event = detection_engine.analyze_event(event_data)
    
    # Write alert node to Neo4j
    log_query = """
    CREATE (alert:Alert {
        id: $id,
        timestamp: $timestamp,
        title: $title,
        description: $description,
        risk_score: $risk_score,
        threat_type: $threat_type,
        confidence: $confidence,
        source_ip: $source_ip,
        accessed_asset: $accessed_asset
    })
    """
    try:
        neo4j_client.execute_query(log_query, {
            "id": processed_event.event_id,
            "timestamp": processed_event.timestamp,
            "title": processed_event.title,
            "description": processed_event.description,
            "risk_score": processed_event.risk_score,
            "threat_type": processed_event.threat_type,
            "confidence": processed_event.confidence,
            "source_ip": processed_event.source_ip,
            "accessed_asset": processed_event.accessed_asset
        })
    except Exception as e:
        logger.error(f"Failed to log honeytoken alert to DB: {e}")

    # Broadcast event via websocket event bus
    # We run this in the event loop since it's async
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(event_bus.broadcast(processed_event))
    loop.close()

# API 1: Fake Premium Transfer API
@router.post("/internal-premium-transfer-api")
async def premium_transfer_api(request: Request, background_tasks: BackgroundTasks):
    """
    Fake honeytoken wire transfer API.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    headers = dict(request.headers)
    
    # Run alert processing as background task so attacker receives quick response (legitimate behaviour)
    background_tasks.add_task(trigger_honeytoken_alert, "/api/v1/internal-premium-transfer-api", "POST", client_ip, headers)
    
    return {
        "status": "processing",
        "transaction_ref": f"TX-PRM-{uuid.uuid4().hex[:8].upper()}",
        "message": "High-value premium transfer queued for validation.",
        "est_completion_ms": 1500
    }

# API 2: Fake Liquidity Dashboard API
@router.get("/admin-liquidity-dashboard")
async def admin_liquidity_dashboard(request: Request, background_tasks: BackgroundTasks):
    """
    Fake honeytoken liquidity dashboard console.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    headers = dict(request.headers)
    
    background_tasks.add_task(trigger_honeytoken_alert, "/api/v1/admin-liquidity-dashboard", "GET", client_ip, headers)
    
    return {
        "status": "nominal",
        "institutional_reserves": {
            "USD": 750000000.0,
            "EUR": 450000000.0,
            "GBP": 120000000.0,
            "JPY": 15000000000.0
        },
        "last_audit_timestamp": datetime.now().isoformat(),
        "reconciliation_active": False
    }

# API 3: Fake Settlement Engine Command
@router.post("/internal-settlement-engine")
async def internal_settlement_engine(request: Request, background_tasks: BackgroundTasks):
    """
    Fake honeytoken bank-to-bank settlement hook.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    headers = dict(request.headers)
    
    background_tasks.add_task(trigger_honeytoken_alert, "/api/v1/internal-settlement-engine", "POST", client_ip, headers)
    
    return {
        "status": "acknowledged",
        "job_id": f"SETTLE-JOB-{uuid.uuid4().hex[:6].upper()}",
        "nodes_responding": 7,
        "clearing_cycle": "EOD-SETTLE-MAIN"
    }
