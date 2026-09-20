import asyncio
import random
import logging
import uuid
from datetime import datetime
try:
    from services.neo4j_client import neo4j_client
    from services.event_bus import event_bus
except ModuleNotFoundError:
    from neo4j_client import neo4j_client
    from event_bus import event_bus
from config import settings
from models.schemas import SecurityEvent

logger = logging.getLogger("nyxvault.mutator")
logging.basicConfig(level=logging.INFO)

class AdaptiveMutator:
    def __init__(self):
        self.is_running = True
        self.mutation_count = 0
        self.loop_task = None

    def start(self):
        if not self.is_running:
            self.is_running = True
            logger.info("Adaptive Mutation Engine resumed.")

    def stop(self):
        if self.is_running:
            self.is_running = False
            logger.info("Adaptive Mutation Engine paused.")

    async def start_loop(self):
        """Starts the mutator execution loop."""
        self.loop_task = asyncio.create_task(self._run_mutations())
        logger.info("Adaptive Mutation Engine background loop started.")

    async def _run_mutations(self):
        # Initial sleep to let database populate and stabilize
        await asyncio.sleep(60)
        while True:
            try:
                if self.is_running:
                    await self.mutate_now()
            except Exception as e:
                logger.error(f"Error in mutation loop: {e}", exc_info=True)
            
            await asyncio.sleep(settings.MUTATION_INTERVAL_MINUTES * 60)

    async def mutate_now(self) -> dict:
        """
        Executes a graph mutation cycle:
        1. Mutates balances on standard accounts (small random fluctuations).
        2. Creates a new honeytoken account.
        3. Creates a new honeytoken API endpoint.
        4. Links them into the graph.
        5. Logs the mutation in the DB and broadcasts a WebSocket notification.
        """
        self.mutation_count += 1
        timestamp = datetime.now().isoformat()
        logger.info(f"Executing Mutation Cycle #{self.mutation_count}...")

        # 1. Mutate balances of standard accounts
        # Randomly adjust balance of 10% of standard accounts by -5% to +5%
        mutate_balance_query = """
        MATCH (a:Account)
        WHERE NOT a.is_honeytoken
        WITH a, rand() as r
        WHERE r < 0.1
        SET a.balance = round(a.balance * (1.0 + (rand() * 0.1 - 0.05)), 2)
        RETURN count(a) as mutated_accounts
        """
        mutated_acc_res = neo4j_client.execute_query(mutate_balance_query)
        mutated_accounts_count = mutated_acc_res[0]["mutated_accounts"] if mutated_acc_res else 0

        # 2. Generate a new Honeytoken Account
        ht_account_names = [
            ("Vault Collateral Account", 880000000.0),
            ("Interbank Clearing Settlement", 520000000.0),
            ("Sovereign Debt Reserves", 2300000000.0),
            ("Structured Trade Liquidity", 940000000.0),
            ("Securitized Assets Fund", 115000000.0)
        ]
        chosen_ht_name, chosen_ht_bal = random.choice(ht_account_names)
        ht_acc_id = f"ACC-HT-MUT-{self.mutation_count}-{random.randint(10, 99)}"
        
        create_ht_account_query = """
        CREATE (a:Account {
            id: $id,
            account_type: $name,
            balance: $balance,
            is_honeytoken: true,
            mutated_cycle: $cycle
        })
        RETURN a.id as id
        """
        neo4j_client.execute_query(create_ht_account_query, {
            "id": ht_acc_id,
            "name": chosen_ht_name,
            "balance": chosen_ht_bal,
            "cycle": self.mutation_count
        })

        # Link this new honeytoken account to a random wealth customer
        link_ht_account_query = """
        MATCH (c:Customer {customer_type: 'wealth'})
        WITH c, rand() as r
        ORDER BY r
        LIMIT 1
        MATCH (a:Account {id: $acc_id})
        CREATE (c)-[:OWNS]->(a)
        RETURN c.name as owner_name
        """
        owner_res = neo4j_client.execute_query(link_ht_account_query, {"acc_id": ht_acc_id})
        owner_name = owner_res[0]["owner_name"] if owner_res else "External Node"

        # 3. Generate a new Honeytoken API
        ht_api_endpoints = [
            ("/api/v1/auth/superuser-escalate", "POST", "Escalate session authorization to administrator level"),
            ("/api/v1/internal-ops-vault", "GET", "Fetch cryptographic secret keys for operations"),
            ("/api/v1/treasury/bypass-limit", "POST", "Bypass standard transaction limits for reserve transfers"),
            ("/api/v1/admin/debug-database", "GET", "Raw administrative database interface shell")
        ]
        chosen_api_path, chosen_api_method, chosen_api_desc = random.choice(ht_api_endpoints)
        # Randomize path slightly to prevent simple string matching by static attackers
        suffix = f"-v{self.mutation_count}"
        mutated_path = chosen_api_path + suffix

        create_ht_api_query = """
        CREATE (api:APIEndpoint {
            path: $path,
            method: $method,
            description: $desc,
            is_honeytoken: true,
            mutated_cycle: $cycle
        })
        RETURN api.path as path
        """
        neo4j_client.execute_query(create_ht_api_query, {
            "path": mutated_path,
            "method": chosen_api_method,
            "desc": chosen_api_desc,
            "cycle": self.mutation_count
        })

        # 4. Create dummy transfers between standard accounts to expand graph relationships
        # Creates 5 transactions to simulate evolving transaction networks
        create_new_transfers_query = """
        MATCH (a1:Account), (a2:Account)
        WHERE NOT a1.is_honeytoken AND NOT a2.is_honeytoken AND a1.id <> a2.id
        WITH a1, a2, rand() as r
        ORDER BY r
        LIMIT 5
        CREATE (a1)-[:TRANSFERRED_TO {
            amount: round(rand() * 1000 + 50, 2),
            timestamp: $timestamp,
            is_mutated: true
        }]->(a2)
        RETURN count(*) as link_count
        """
        link_res = neo4j_client.execute_query(create_new_transfers_query, {"timestamp": timestamp})
        link_count = link_res[0]["link_count"] if link_res else 0

        # Save mutation tracking node in Neo4j
        save_mutation_query = """
        MERGE (tracker:MutationTracker {id: 'global'})
        SET tracker.mutation_count = $count,
            tracker.last_mutated = $timestamp
        """
        neo4j_client.execute_query(save_mutation_query, {
            "count": self.mutation_count,
            "timestamp": timestamp
        })

        # 5. Broadcast mutation event via WebSockets
        mutation_details = {
            "mutation_cycle": self.mutation_count,
            "mutated_accounts_count": mutated_accounts_count,
            "new_honeytoken_account": f"{chosen_ht_name} ({ht_acc_id}) owned by {owner_name}",
            "new_honeytoken_api": f"{chosen_api_method} {mutated_path}",
            "new_transaction_trails": link_count
        }

        mutation_event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type="mutation",
            timestamp=timestamp,
            title=f"Deception Mutation #{self.mutation_count}",
            description=f"Deception graph adapted. Injected 1 new honeytoken account, 1 new honeytoken API, and refreshed transaction trails.",
            risk_score=0.0,
            threat_type=None,
            confidence=1.0,
            details=mutation_details
        )
        
        await event_bus.broadcast(mutation_event)
        logger.info(f"Mutation Cycle #{self.mutation_count} finished & broadcasted.")
        
        return mutation_details

# Global mutator instance
mutator = AdaptiveMutator()
