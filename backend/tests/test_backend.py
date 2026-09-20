import pytest
from services.detector import ThreatDetectionEngine, random_honeytoken_score
from services.explainer import ai_explainer
from services.threat_scorer import ThreatScoringEngine
from models.schemas import SecurityEvent

def test_honeytoken_score():
    score = random_honeytoken_score()
    assert 90.0 <= score <= 100.0

def test_detector_normal_event():
    engine = ThreatDetectionEngine()
    
    event_data = {
        "is_honeytoken": False,
        "accessed_asset": "/api/v1/accounts",
        "asset_type": "APIEndpoint",
        "username": "t_jones",
        "access_frequency": 2.0,
        "amount": 0.0,
        "avg_balance": 0.0,
        "unauthorized": False,
        "source_ip": "192.168.1.45"
    }
    
    processed = engine.analyze_event(event_data)
    assert processed.risk_score < 50.0
    assert processed.threat_type is None
    assert processed.confidence > 0.0
    assert processed.event_type == "detection"
    assert processed.accessed_asset == "/api/v1/accounts"

def test_detector_honeytoken_api_event():
    engine = ThreatDetectionEngine()
    
    event_data = {
        "is_honeytoken": True,
        "accessed_asset": "/api/v1/internal-premium-transfer-api",
        "asset_type": "APIEndpoint",
        "username": "recon_bot",
        "access_frequency": 1.0,
        "amount": 0.0,
        "avg_balance": 0.0,
        "unauthorized": True,
        "source_ip": "10.0.12.84"
    }
    
    processed = engine.analyze_event(event_data)
    assert processed.risk_score >= 90.0
    assert processed.threat_type == "API Reconnaissance"
    assert processed.confidence == 1.0
    assert "premium-transfer-api" in processed.accessed_asset

def test_ai_explainer_critical_honeytoken():
    # Verify Honeytoken traps instantly generate Critical incident alerts
    payload = {
        "id": "ACC-HT-8921",
        "label": "Account",
        "name": "Corporate Reserve Account",
        "threat_score": 98.0,
        "risk_level": "CRITICAL",
        "is_honeytoken": True,
        "anomaly_score": 0.1,
        "is_anomalous": False
    }
    
    res = ai_explainer.generate_explanation(payload)
    assert "honeytoken" in res["explanation"].lower()
    assert "deception trap" in res["explanation"].lower()
    assert res["confidence"] == 1.0
    assert "IMMEDIATE ACTION" in res["recommended_action"]

def test_ai_explainer_fraud_ring_anomaly():
    # Verify composite explanation contains anomaly and fraud ring details
    payload = {
        "id": "ACC-9921",
        "label": "Account",
        "name": "Retail Savings",
        "threat_score": 85.0,
        "risk_level": "CRITICAL",
        "is_honeytoken": False,
        "anomaly_score": 0.92,
        "is_anomalous": True,
        "fraud_ring_id": "FR-SCC-102",
        "fraud_ring_size": 4,
        "fraud_ring_risk": 82.5,
        "blast_radius": {
            "financial_exposure": 12000000.0,
            "formatted_exposure": "₹1.20 Crore",
            "affected_customers": 5
        },
        "attack_path": {
            "attack_probability": 78.5,
            "target_asset": {"name": "Reserve Ledger API"},
            "path_nodes": [{"id": "ACC-9921"}, {"id": "API-HT"}]
        }
    }
    
    res = ai_explainer.generate_explanation(payload)
    assert "anomaly score: 0.92" in res["explanation"].lower()
    assert "fraud ring 'fr-scc-102'" in res["explanation"].lower()
    assert "financial blast radius" in res["explanation"].lower()
    assert "₹1.20 crore" in res["explanation"].lower()
    assert "78.5% probability" in res["explanation"].lower()
    assert res["confidence"] >= 0.90
    assert "temporary account suspension" in res["recommended_action"].lower()
