import asyncio
import random
import logging
from datetime import datetime
import uuid

try:
    from services.neo4j_client import neo4j_client
    from services.detector import detection_engine
    from services.event_bus import event_bus
    from config import settings
    from models.schemas import SecurityEvent
except ModuleNotFoundError:
    from neo4j_client import neo4j_client
    from detector import detection_engine
    from event_bus import event_bus
    from config import settings
    from models.schemas import SecurityEvent

logger = logging.getLogger("nyxvault.simulator")
logging.basicConfig(level=logging.INFO)

class AttackSimulator:
    def __init__(self):
        self.is_running = True
        self.loop_task = None

    def start(self):
        if not self.is_running:
            self.is_running = True
            logger.info("Attack Simulator resumed.")

    def stop(self):
        if self.is_running:
            self.is_running = False
            logger.info("Attack Simulator paused.")

    async def start_loop(self):
        """Starts the simulator task execution loop."""
        self.loop_task = asyncio.create_task(self._run_simulation())
        logger.info("Attack Simulator background loop started.")

    async def _run_simulation(self):
        while True:
            try:
                if self.is_running:
                    # 75% normal event, 25% attack simulation event
                    if random.random() < 0.75:
                        await self.generate_event(is_attack=False)
                    else:
                        await self.generate_event(is_attack=True)
            except Exception as e:
                logger.error(f"Error in simulation loop: {e}", exc_info=True)
            
            await asyncio.sleep(settings.SIMULATION_INTERVAL_SECONDS)

    async def generate_event(self, is_attack: bool = False, attack_type: str = None) -> SecurityEvent:
        """
        Generates and processes a mock activity or attack event.
        """
        accounts = self._get_db_accounts()
        apis = self._get_db_apis()
        creds = self._get_db_credentials()

        if not accounts or not apis or not creds:
            logger.warning("Database empty or not accessible. Skipping event generation.")
            return None

        event_data = {}
        source_ips = ["192.168.1.45", "10.0.4.19", "172.16.89.4", "10.240.0.12"]
        event_data["source_ip"] = random.choice(source_ips)

        if not is_attack:
            # Normal User Activity
            normal_cred = random.choice([c for c in creds if not c.get("is_honeytoken", False)])
            normal_acc = random.choice([a for a in accounts if not a.get("is_honeytoken", False)])
            normal_api = random.choice([api for api in apis if not api.get("is_honeytoken", False)])

            if random.random() < 0.5:
                # Normal API Request
                event_data.update({
                    "username": normal_cred["username"],
                    "accessed_asset": normal_api["path"],
                    "asset_type": "APIEndpoint",
                    "is_honeytoken": False,
                    "access_frequency": float(random.randint(1, 3)),
                    "amount": 0.0,
                    "avg_balance": 0.0,
                    "unauthorized": False
                })
            else:
                # Normal transaction execution
                event_data.update({
                    "username": normal_cred["username"],
                    "accessed_asset": normal_acc["id"],
                    "asset_type": "Account",
                    "is_honeytoken": False,
                    "access_frequency": 1.0,
                    "amount": round(random.uniform(5.0, 500.0), 2),
                    "avg_balance": normal_acc["balance"],
                    "unauthorized": False
                })
                self._mutate_db_balance(normal_acc["id"], -event_data["amount"])
        else:
            # Cyber Security Threat Scenarios
            types = ["insider_threat", "credential_theft", "api_recon", "transaction_exploration", "lateral_movement"]
            chosen_type = attack_type or random.choice(types)

            if chosen_type == "insider_threat":
                normal_cred = random.choice([c for c in creds if not c.get("is_honeytoken", False)])
                target_acc = random.choice(accounts)
                
                event_data.update({
                    "username": normal_cred["username"],
                    "accessed_asset": target_acc["id"],
                    "asset_type": "Account",
                    "is_honeytoken": target_acc.get("is_honeytoken", False),
                    "access_frequency": 1.0,
                    "amount": 0.0,
                    "avg_balance": target_acc["balance"],
                    "unauthorized": True
                })
            
            elif chosen_type == "credential_theft":
                honey_cred = random.choice([c for c in creds if c.get("is_honeytoken", True)])
                target_acc = random.choice(accounts)

                event_data.update({
                    "username": honey_cred["username"],
                    "accessed_asset": target_acc["id"],
                    "asset_type": "EmployeeCredential",
                    "is_honeytoken": True,
                    "access_frequency": 1.0,
                    "amount": 0.0,
                    "avg_balance": target_acc["balance"],
                    "unauthorized": True
                })

            elif chosen_type == "api_recon":
                honey_api = random.choice([api for api in apis if api.get("is_honeytoken", True)])
                normal_cred = random.choice(creds)
                
                event_data.update({
                    "username": normal_cred["username"],
                    "accessed_asset": honey_api["path"],
                    "asset_type": "APIEndpoint",
                    "is_honeytoken": True,
                    "access_frequency": float(random.randint(15, 45)),
                    "amount": 0.0,
                    "avg_balance": 0.0,
                    "unauthorized": True
                })

            elif chosen_type == "transaction_exploration":
                normal_cred = random.choice(creds)
                wealth_accs = [a for a in accounts if a["balance"] > 100000.0]
                target_acc = random.choice(wealth_accs) if wealth_accs else random.choice(accounts)
                
                event_data.update({
                    "username": normal_cred["username"],
                    "accessed_asset": target_acc["id"],
                    "asset_type": "Account",
                    "is_honeytoken": target_acc.get("is_honeytoken", False),
                    "access_frequency": 1.0,
                    "amount": round(random.uniform(250000.0, 950000.0), 2),
                    "avg_balance": target_acc["balance"],
                    "unauthorized": False
                })
                self._mutate_db_balance(target_acc["id"], -event_data["amount"])

            elif chosen_type == "lateral_movement":
                # Attacker accesses regular account, hops to admin credential, and hits Honeytoken API
                normal_cred = random.choice([c for c in creds if not c.get("is_honeytoken", False)])
                admin_cred = random.choice([c for c in creds if c.get("is_honeytoken", True)])
                honey_api = random.choice([api for api in apis if api.get("is_honeytoken", True)])

                # Log lateral steps
                event_data.update({
                    "username": normal_cred["username"],
                    "accessed_asset": admin_cred["username"],
                    "asset_type": "EmployeeCredential",
                    "is_honeytoken": True, # Triggers alert instantly on the credential jump
                    "access_frequency": 2.0,
                    "amount": 0.0,
                    "avg_balance": 0.0,
                    "unauthorized": True
                })
                
                # Write an explicit log in Neo4j to simulate the compromise path
                self._create_accessed_edge(admin_cred["username"], honey_api["path"])

        # Feed to detection
        processed_event = detection_engine.analyze_event(event_data)
        
        if is_attack:
            attack_event = SecurityEvent(
                event_id=processed_event.event_id + "-sim",
                event_type="attack",
                timestamp=processed_event.timestamp,
                title=f"Attack Triggered: {processed_event.threat_type or chosen_type}",
                description=f"Attacker initiated simulation activity matching threat pattern: {processed_event.threat_type or chosen_type}.",
                risk_score=processed_event.risk_score,
                threat_type=processed_event.threat_type or "Intrusion",
                confidence=processed_event.confidence,
                source_ip=processed_event.source_ip,
                accessed_asset=processed_event.accessed_asset,
                details=event_data
            )
            await event_bus.broadcast(attack_event)
            await asyncio.sleep(1.0)

        await event_bus.broadcast(processed_event)
        
        if processed_event.risk_score > settings.ALERT_THRESHOLD * 100:
            logger.warning(f"HIGH RISK THREAT DETECTED: {processed_event.title} [Risk: {processed_event.risk_score}]")
            self._log_alert_to_db(processed_event)

        return processed_event

    def inject_fraud_ring_simulation(self) -> dict:
        """
        Creates a circular transaction loop (fraud ring) between 3 newly generated Accounts
        connected to a Customer. This SCC will be detected during the next graph analytics run.
        """
        timestamp = datetime.now().isoformat()
        
        # 1. Create a Customer
        cust_id = f"CUST-FRD-{random.randint(100, 999)}"
        create_cust_query = """
        CREATE (c:Customer {
            id: $id,
            name: $name,
            customer_type: 'corporate',
            risk_score: 45.0
        })
        """
        neo4j_client.execute_query(create_cust_query, {
            "id": cust_id,
            "name": f"Shell Corp {random.randint(10, 99)} Ltd"
        })

        # 2. Create 3 Accounts linked to this customer
        accs = [
            {"id": f"ACC-FRD-A-{random.randint(10, 99)}", "type": "checking", "bal": 850000.0},
            {"id": f"ACC-FRD-B-{random.randint(10, 99)}", "type": "checking", "bal": 920000.0},
            {"id": f"ACC-FRD-C-{random.randint(10, 99)}", "type": "savings", "bal": 780000.0}
        ]

        for acc in accs:
            create_acc_query = """
            CREATE (a:Account {
                id: $id,
                account_type: $type,
                balance: $bal,
                is_honeytoken: false,
                account_age: 45
            })
            """
            neo4j_client.execute_query(create_acc_query, {
                "id": acc["id"],
                "type": acc["type"],
                "bal": acc["bal"]
            })
            
            # Link to Customer
            neo4j_client.execute_query("""
            MATCH (c:Customer {id: $c_id})
            MATCH (a:Account {id: $a_id})
            CREATE (c)-[:OWNS]->(a)
            """, {"c_id": cust_id, "a_id": acc["id"]})

        # 3. Create the circular transaction edges
        # A -> B -> C -> A
        transfers = [
            (accs[0]["id"], accs[1]["id"], 250000.0),
            (accs[1]["id"], accs[2]["id"], 240000.0),
            (accs[2]["id"], accs[0]["id"], 260000.0)
        ]

        for src, dest, amt in transfers:
            neo4j_client.execute_query("""
            MATCH (a1:Account {id: $s})
            MATCH (a2:Account {id: $t})
            CREATE (a1)-[:TRANSFERRED_TO {
                amount: $amt,
                timestamp: $timestamp
            }]->(a2)
            """, {"s": src, "t": dest, "amt": amt, "timestamp": timestamp})

        # Broadcast the injection alert
        details = {
            "fraud_customer": cust_id,
            "fraud_accounts": [a["id"] for a in accs],
            "circular_loop": f"{accs[0]['id']} -> {accs[1]['id']} -> {accs[2]['id']} -> {accs[0]['id']}"
        }
        
        sim_event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type="attack",
            timestamp=timestamp,
            title="Simulation: Fraud Ring Injected",
            description=f"Injected circular laundering transaction loop linking 3 accounts under Corporate Client '{cust_id}'. Run risk intelligence to detect.",
            risk_score=75.0,
            threat_type="Fraud Ring Activity",
            confidence=0.90,
            details=details
        )
        
        # We also broadcast this event async using a background task helper or direct run
        return details

    # --- Helper DB Operations ---
    def _create_accessed_edge(self, s_id: str, t_id: str):
        query = """
        MATCH (n1), (n2)
        WHERE (n1.id = $s OR n1.username = $s) AND (n2.id = $t OR n2.path = $t)
        CREATE (n1)-[:ACCESSED {timestamp: datetime().isoformat()}]->(n2)
        """
        try:
            neo4j_client.execute_query(query, {"s": s_id, "t": t_id})
        except Exception as e:
            logger.error(f"Failed to write ACCESSED relation: {e}")

    def _get_db_accounts(self):
        query = "MATCH (a:Account) RETURN a.id as id, a.balance as balance, a.is_honeytoken as is_honeytoken"
        try:
            return neo4j_client.execute_query(query)
        except Exception:
            return []

    def _get_db_apis(self):
        query = "MATCH (api:APIEndpoint) RETURN api.path as path, api.is_honeytoken as is_honeytoken"
        try:
            return neo4j_client.execute_query(query)
        except Exception:
            return []

    def _get_db_credentials(self):
        query = "MATCH (e:EmployeeCredential) RETURN e.username as username, e.is_honeytoken as is_honeytoken"
        try:
            return neo4j_client.execute_query(query)
        except Exception:
            return []

    def _mutate_db_balance(self, acc_id: str, diff: float):
        query = """
        MATCH (a:Account {id: $id})
        SET a.balance = a.balance + $diff
        """
        try:
            neo4j_client.execute_query(query, {"id": acc_id, "diff": diff})
        except Exception as e:
            logger.error(f"Failed to update balance for {acc_id}: {e}")

    def _log_alert_to_db(self, event: SecurityEvent):
        query = """
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
            neo4j_client.execute_query(query, {
                "id": event.event_id,
                "timestamp": event.timestamp,
                "title": event.title,
                "description": event.description,
                "risk_score": event.risk_score,
                "threat_type": event.threat_type or "Anomaly",
                "confidence": event.confidence or 0.0,
                "source_ip": event.source_ip or "unknown",
                "accessed_asset": event.accessed_asset or "none"
            })
        except Exception as e:
            logger.error(f"Failed to save alert node: {e}")

# Global simulator instance
simulator = AttackSimulator()
