import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from services.neo4j_client import neo4j_client
from services.generator import generate_synthetic_data
from services.simulator import simulator
from services.mutator import mutator
from services.event_bus import event_bus

# Import routers
from api.stats import router as stats_router
from api.graph import router as graph_router
from api.honeytokens import router as honeytoken_router
from api.simulation import router as simulation_router
from api.risk import router as risk_router

# Setup logging
logger = logging.getLogger("nyxvault.main")
logging.basicConfig(level=logging.INFO)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup Actions ---
    logger.info("Initializing NyxVault Lite Backend...")
    
    # 1. Verify Neo4j connectivity
    connected = neo4j_client.verify_connectivity()
    if connected:
        logger.info("Connected to Neo4j database successfully.")
        
        # 2. Check if DB is empty and auto-seed if necessary
        try:
            check_empty_query = "MATCH (n) RETURN count(n) as count"
            res = neo4j_client.execute_query(check_empty_query)
            count = res[0]["count"] if res else 0
            if count == 0:
                logger.info("Database is empty. Triggering automatic seeding...")
                generate_synthetic_data()
            else:
                logger.info(f"Database contains {count} nodes. Skipping auto-seed.")
                
            # Trigger initial threat scoring run to populate intelligence variables
            logger.info("Triggering initial threat intelligence scoring run...")
            from services.anomaly_detector import anomaly_detector
            from services.fraud_ring import fraud_detector
            from services.threat_scorer import threat_scorer
            
            anomaly_detector.detect_anomalies()
            fraud_detector.detect_fraud_rings()
            threat_scorer.calculate_and_persist_scores()
            logger.info("Initial threat scoring run completed.")
            
        except Exception as e:
            logger.error(f"Failed to run database check/seed/scoring query: {e}", exc_info=True)
    else:
        logger.error("COULD NOT CONNECT TO NEO4J DATABASE. Seeding & background tasks may fail.")

    # 3. Start Attack Simulator background task loop
    await simulator.start_loop()
    
    # 4. Start Adaptive Mutation Engine background task loop
    await mutator.start_loop()
    
    yield
    
    # --- Shutdown Actions ---
    logger.info("Shutting down NyxVault Lite Backend...")
    # Close Neo4j connection
    neo4j_client.close()

app = FastAPI(
    title="NyxVault Lite API",
    description="Adaptive AI Deception System for Banking Threat Detection",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS for Frontend interaction
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict to frontend url
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(stats_router, prefix="/api/v1")
app.include_router(graph_router, prefix="/api/v1")
app.include_router(honeytoken_router, prefix="/api/v1")
app.include_router(simulation_router, prefix="/api/v1")
app.include_router(risk_router, prefix="/api/v1")

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "NyxVault Lite Backend",
        "version": "1.0.0",
        "database_connected": neo4j_client.verify_connectivity()
    }

@app.get("/health")
def health_check():
    """Lightweight health check endpoint for AWS Application Load Balancer."""
    return {"status": "healthy"}

# WebSocket Endpoint for Event Streaming
@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await event_bus.connect(websocket)
    try:
        # Keep connection alive and listen for any incoming messages from client (optional)
        while True:
            data = await websocket.receive_text()
            logger.info(f"Received message from client: {data}")
    except WebSocketDisconnect:
        event_bus.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        event_bus.disconnect(websocket)
