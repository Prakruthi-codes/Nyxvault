from fastapi import APIRouter, HTTPException, BackgroundTasks
from models.schemas import SimulationTrigger, SimulationStatusResponse, MutationStatusResponse
from services.simulator import simulator
from services.mutator import mutator
from services.event_bus import event_bus
from models.schemas import SecurityEvent
from config import settings
import logging
import uuid
from datetime import datetime

logger = logging.getLogger("nyxvault.api.simulation")
router = APIRouter(tags=["Simulation & Deception Controls"])

@router.get("/simulation/status", response_model=SimulationStatusResponse)
def get_simulation_status():
    """Returns the running status of the Attack Simulator."""
    return SimulationStatusResponse(
        is_running=simulator.is_running,
        interval_seconds=settings.SIMULATION_INTERVAL_SECONDS
    )

@router.post("/simulation/start", response_model=SimulationStatusResponse)
def start_simulation():
    """Resumes the Attack Simulator background loop."""
    simulator.start()
    return SimulationStatusResponse(
        is_running=simulator.is_running,
        interval_seconds=settings.SIMULATION_INTERVAL_SECONDS
    )

@router.post("/simulation/stop", response_model=SimulationStatusResponse)
def stop_simulation():
    """Pauses the Attack Simulator background loop."""
    simulator.stop()
    return SimulationStatusResponse(
        is_running=simulator.is_running,
        interval_seconds=settings.SIMULATION_INTERVAL_SECONDS
    )

@router.post("/simulation/trigger")
async def trigger_simulation_attack(trigger: SimulationTrigger, background_tasks: BackgroundTasks):
    """
    Manually triggers a specific cybersecurity attack simulation event.
    """
    valid_attacks = ["insider_threat", "credential_theft", "api_recon", "transaction_exploration", "lateral_movement"]
    if trigger.attack_type not in valid_attacks:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid attack type. Must be one of {valid_attacks}"
        )
    
    background_tasks.add_task(simulator.generate_event, is_attack=True, attack_type=trigger.attack_type)
    
    return {
        "status": "triggered",
        "attack_type": trigger.attack_type,
        "message": f"Simulation event for '{trigger.attack_type}' has been queued."
    }

# --- Upgraded Specific Scenario Endpoints ---

@router.post("/simulation/credential-theft")
async def trigger_credential_theft_scenario(background_tasks: BackgroundTasks):
    """
    Queues a Credential Theft scenario: uses a privileged honeytoken credential
    to access multiple standard assets.
    """
    background_tasks.add_task(simulator.generate_event, is_attack=True, attack_type="credential_theft")
    return {
        "status": "triggered",
        "scenario": "Credential Theft",
        "message": "Honeytoken credential theft activity has been queued."
    }

@router.post("/simulation/lateral-movement")
async def trigger_lateral_movement_scenario(background_tasks: BackgroundTasks):
    """
    Queues a Multi-Hop Lateral Movement scenario: compromises customer node,
    hops to admin credential, and touches restricted Honeytoken APIs.
    """
    background_tasks.add_task(simulator.generate_event, is_attack=True, attack_type="lateral_movement")
    return {
        "status": "triggered",
        "scenario": "Lateral Movement",
        "message": "Multi-hop lateral movement threat has been queued."
    }

@router.post("/simulation/fraud-ring")
async def trigger_fraud_ring_scenario(background_tasks: BackgroundTasks):
    """
    Immediately injects a new circular transaction loop (fraud ring) in Neo4j.
    Connects 3 new accounts under a corporate shell client.
    """
    # Execute injection and capture details
    details = simulator.inject_fraud_ring_simulation()
    
    # Broadcast notice event via Websocket Event Bus
    timestamp = datetime.now().isoformat()
    ring_event = SecurityEvent(
        event_id=str(uuid.uuid4()),
        event_type="attack",
        timestamp=timestamp,
        title="Simulation: Fraud Ring Active",
        description=f"Circular transaction loops established linking accounts: {', '.join(details['fraud_accounts'])}.",
        risk_score=75.0,
        threat_type="Fraud Ring Activity",
        confidence=0.90,
        details=details
    )
    await event_bus.broadcast(ring_event)

    return {
        "status": "injected",
        "scenario": "Fraud Ring Loop",
        "details": details
    }

# --- Mutation controls ---

@router.get("/mutation/status", response_model=MutationStatusResponse)
def get_mutation_status():
    """Returns the running status of the Adaptive Mutation Engine."""
    return MutationStatusResponse(
        is_running=mutator.is_running,
        interval_minutes=settings.MUTATION_INTERVAL_MINUTES,
        mutation_count=mutator.mutation_count
    )

@router.post("/mutation/start", response_model=MutationStatusResponse)
def start_mutation():
    """Resumes the Mutation Engine background loop."""
    mutator.start()
    return MutationStatusResponse(
        is_running=mutator.is_running,
        interval_minutes=settings.MUTATION_INTERVAL_MINUTES,
        mutation_count=mutator.mutation_count
    )

@router.post("/mutation/stop", response_model=MutationStatusResponse)
def stop_mutation():
    """Pauses the Mutation Engine background loop."""
    mutator.stop()
    return MutationStatusResponse(
        is_running=mutator.is_running,
        interval_minutes=settings.MUTATION_INTERVAL_MINUTES,
        mutation_count=mutator.mutation_count
    )

@router.post("/mutation/trigger")
async def trigger_mutation_now(background_tasks: BackgroundTasks):
    """
    Manually triggers a graph mutation cycle immediately.
    """
    background_tasks.add_task(mutator.mutate_now)
    return {
        "status": "triggered",
        "message": "Adaptive mutation process has been queued."
    }
