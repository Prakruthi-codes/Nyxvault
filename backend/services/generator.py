import os
import random
import logging
from datetime import datetime, timedelta
from faker import Faker
try:
    from services.neo4j_client import neo4j_client
except ModuleNotFoundError:
    from neo4j_client import neo4j_client

logger = logging.getLogger("nyxvault.generator")
logging.basicConfig(level=logging.INFO)

fake = Faker()

def generate_synthetic_data(num_customers: int = 100, num_accounts: int = 300, num_transactions: int = 2000):
    """
    Clears Neo4j database and populates it with synthetic banking data.
    Ensures constraints, customers, accounts, transactions, and honeytokens are generated.
    """
    if not neo4j_client.verify_connectivity():
        logger.error("Cannot connect to Neo4j. Skipping data generation.")
        return

    logger.info("Starting synthetic banking ecosystem generation...")

    # Step 1: Clear database and setup constraints
    clear_db_query = """
    MATCH (n) DETACH DELETE n
    """
    neo4j_client.execute_query(clear_db_query)
    logger.info("Cleared existing database nodes and relationships.")

    # Create constraints if supported (optional but good practice for unique keys)
    # Neo4j 5 syntax for constraints
    try:
        neo4j_client.execute_query("CREATE CONSTRAINT customer_id_unique IF NOT EXISTS FOR (c:Customer) REQUIRE c.id IS UNIQUE")
        neo4j_client.execute_query("CREATE CONSTRAINT account_id_unique IF NOT EXISTS FOR (a:Account) REQUIRE a.id IS UNIQUE")
        neo4j_client.execute_query("CREATE CONSTRAINT api_path_unique IF NOT EXISTS FOR (api:APIEndpoint) REQUIRE api.path IS UNIQUE")
        neo4j_client.execute_query("CREATE CONSTRAINT cred_user_unique IF NOT EXISTS FOR (e:EmployeeCredential) REQUIRE e.username IS UNIQUE")
        logger.info("Database constraints created.")
    except Exception as e:
        logger.warning(f"Could not create constraints (might be Neo4j edition limitation): {e}")

    # Step 2: Generate Customers
    customers = []
    customer_types = ["retail", "corporate", "wealth"]
    logger.info(f"Generating {num_customers} customers...")
    
    for i in range(num_customers):
        c_id = f"CUST-{1000 + i}"
        name = fake.name()
        c_type = random.choice(customer_types)
        # Low default risk score, high-risk flag etc will be adjusted by simulator
        risk_score = round(random.uniform(5.0, 30.0), 2)
        customers.append({
            "id": c_id,
            "name": name,
            "customer_type": c_type,
            "risk_score": risk_score
        })

    # Insert customers in batches
    insert_customers_query = """
    UNWIND $batch as cust
    CREATE (c:Customer {
        id: cust.id,
        name: cust.name,
        customer_type: cust.customer_type,
        risk_score: cust.risk_score
    })
    """
    neo4j_client.execute_query(insert_customers_query, {"batch": customers})
    logger.info(f"Inserted {num_customers} customers.")

    # Step 3: Generate Accounts (minimum num_accounts)
    # Assign 2 to 4 accounts per customer until we reach target
    accounts = []
    account_types = ["checking", "savings", "investment"]
    account_counter = 100000
    
    logger.info(f"Generating accounts and OWNS relationships...")
    
    customer_owns_relations = []
    
    # First, make sure every customer gets at least one checking account
    for cust in customers:
        acc_id = f"ACC-{account_counter}"
        account_counter += 1
        acc_type = "checking"
        balance = round(random.uniform(500.0, 50000.0), 2)
        
        accounts.append({
            "id": acc_id,
            "account_type": acc_type,
            "balance": balance,
            "is_honeytoken": False
        })
        
        customer_owns_relations.append({
            "customer_id": cust["id"],
            "account_id": acc_id
        })

    # Generate additional accounts to reach num_accounts
    remaining_accounts = max(0, num_accounts - len(customers))
    for _ in range(remaining_accounts):
        acc_id = f"ACC-{account_counter}"
        account_counter += 1
        acc_type = random.choice(account_types)
        
        # Corporate or wealth customers get larger balances
        cust = random.choice(customers)
        if cust["customer_type"] == "corporate":
            balance = round(random.uniform(50000.0, 1000000.0), 2)
        elif cust["customer_type"] == "wealth":
            balance = round(random.uniform(100000.0, 5000000.0), 2)
        else:
            balance = round(random.uniform(100.0, 15000.0), 2)

        accounts.append({
            "id": acc_id,
            "account_type": acc_type,
            "balance": balance,
            "is_honeytoken": False
        })
        
        customer_owns_relations.append({
            "customer_id": cust["id"],
            "account_id": acc_id
        })

    # Insert accounts in batch
    insert_accounts_query = """
    UNWIND $batch as acc
    CREATE (a:Account {
        id: acc.id,
        account_type: acc.account_type,
        balance: acc.balance,
        is_honeytoken: acc.is_honeytoken
    })
    """
    neo4j_client.execute_query(insert_accounts_query, {"batch": accounts})
    logger.info(f"Inserted {len(accounts)} standard accounts.")

    # Insert OWNS relationships in batch
    insert_owns_query = """
    UNWIND $batch as rel
    MATCH (c:Customer {id: rel.customer_id})
    MATCH (a:Account {id: rel.account_id})
    CREATE (c)-[:OWNS]->(a)
    """
    neo4j_client.execute_query(insert_owns_query, {"batch": customer_owns_relations})
    logger.info("Linked customers to standard accounts via OWNS.")

    # Step 4: Generate Cognitive Honeytokens
    logger.info("Generating Cognitive Honeytoken Accounts...")
    honeytoken_accounts = [
        {"id": "ACC-HT-8921", "account_type": "Corporate Reserve Account", "balance": 450000000.0, "is_honeytoken": True},
        {"id": "ACC-HT-1102", "account_type": "Emergency Liquidity Account", "balance": 750000000.0, "is_honeytoken": True},
        {"id": "ACC-HT-4829", "account_type": "Treasury Settlement Account", "balance": 1200000000.0, "is_honeytoken": True},
        {"id": "ACC-HT-6029", "account_type": "Internal Operations Clearing", "balance": 35000000.0, "is_honeytoken": True},
        {"id": "ACC-HT-3391", "account_type": "High-Yield Custody Account", "balance": 180000000.0, "is_honeytoken": True}
    ]
    
    # Link honeytoken accounts to synthetic highly privileged customers (or standard ones to make them look hidden)
    # We will choose a few wealth/corporate customers to "own" these honeytoken accounts, so they appear inside the graph naturally.
    honey_owns_relations = []
    for h_acc in honeytoken_accounts:
        cust = random.choice([c for c in customers if c["customer_type"] in ["corporate", "wealth"]])
        honey_owns_relations.append({
            "customer_id": cust["id"],
            "account_id": h_acc["id"]
        })
        
    neo4j_client.execute_query(insert_accounts_query, {"batch": honeytoken_accounts})
    neo4j_client.execute_query(insert_owns_query, {"batch": honey_owns_relations})
    logger.info("Generated and linked 5 Honeytoken accounts.")

    # Combine account list for transaction generation (excluding honeytokens from source/dest of normal transactions)
    standard_acc_ids = [acc["id"] for acc in accounts]

    # Step 5: Generate Transactions (minimum num_transactions)
    logger.info(f"Generating {num_transactions} transactions...")
    transactions = []
    start_time = datetime.now() - timedelta(days=30)
    
    # We want to create transaction trails. To keep the graph realistic,
    # let's create a scale-free network. Some accounts (hubs) are more active than others.
    # We'll assign activities to accounts.
    account_weights = [random.randint(1, 10) for _ in range(len(standard_acc_ids))]
    
    for _ in range(num_transactions):
        # Pick sender & receiver using weights to create hubs
        sender_id, receiver_id = random.choices(standard_acc_ids, weights=account_weights, k=2)
        while sender_id == receiver_id:
            receiver_id = random.choice(standard_acc_ids)

        amount = round(random.expovariate(1.0 / 100.0) + random.uniform(1.0, 20.0), 2)
        # Cap amount
        amount = min(amount, 100000.0)
        
        # Random timestamp over the past 30 days
        seconds_offset = random.randint(0, 30 * 24 * 3600)
        tx_time = start_time + timedelta(seconds=seconds_offset)
        
        transactions.append({
            "sender": sender_id,
            "receiver": receiver_id,
            "amount": amount,
            "timestamp": tx_time.isoformat()
        })

    # Bulk insert transactions
    insert_transactions_query = """
    UNWIND $batch as tx
    MATCH (sender:Account {id: tx.sender})
    MATCH (receiver:Account {id: tx.receiver})
    CREATE (sender)-[:TRANSFERRED_TO {
        amount: tx.amount,
        timestamp: tx.timestamp
    }]->(receiver)
    """
    neo4j_client.execute_query(insert_transactions_query, {"batch": transactions})
    logger.info(f"Inserted {num_transactions} transactions.")

    # Step 6: Generate APIs
    logger.info("Generating APIs (including honeytokens)...")
    apis = [
        # Normal APIs
        {"path": "/api/v1/accounts", "method": "GET", "description": "Retrieve accounts catalog", "is_honeytoken": False},
        {"path": "/api/v1/transactions", "method": "GET/POST", "description": "Retrieve history or initiate transfers", "is_honeytoken": False},
        {"path": "/api/v1/customers", "method": "GET", "description": "Retrieve profile details", "is_honeytoken": False},
        {"path": "/api/v1/auth/login", "method": "POST", "description": "Standard login endpoint", "is_honeytoken": False},
        # Honeytoken APIs
        {"path": "/api/v1/internal-premium-transfer-api", "method": "POST", "description": "Bypassed wire transfer endpoint for premium accounts", "is_honeytoken": True},
        {"path": "/api/v1/admin-liquidity-dashboard", "method": "GET", "description": "Admin console showing institutional liquidity reserves", "is_honeytoken": True},
        {"path": "/api/v1/internal-settlement-engine", "method": "POST", "description": "Bank clearing & settlement direct command", "is_honeytoken": True}
    ]
    
    insert_apis_query = """
    UNWIND $batch as api
    CREATE (api_node:APIEndpoint {
        path: api.path,
        method: api.method,
        description: api.description,
        is_honeytoken: api.is_honeytoken
    })
    """
    neo4j_client.execute_query(insert_apis_query, {"batch": apis})
    logger.info("Inserted API endpoints.")

    # Step 7: Generate Employee Credentials
    logger.info("Generating employee credentials...")
    credentials = [
        # Normal Employee Credentials
        {"username": "t_jones", "role": "teller", "employee_id": "EMP-0010", "is_honeytoken": False},
        {"username": "s_smith", "role": "teller", "employee_id": "EMP-0012", "is_honeytoken": False},
        {"username": "m_gardner", "role": "customer_support", "employee_id": "EMP-0015", "is_honeytoken": False},
        {"username": "j_adams", "role": "loan_officer", "employee_id": "EMP-0021", "is_honeytoken": False},
        {"username": "e_baker", "role": "compliance_analyst", "employee_id": "EMP-0035", "is_honeytoken": False},
        {"username": "sys_reconciliation", "role": "batch_job", "employee_id": "EMP-0080", "is_honeytoken": False},
        # Honeytoken credentials (look highly privileged)
        {"username": "admin_liquidity", "role": "treasury_admin", "employee_id": "EMP-0492", "is_honeytoken": True},
        {"username": "settlement_system", "role": "system_account", "employee_id": "EMP-0921", "is_honeytoken": True},
        {"username": "reserve_controller", "role": "treasury_controller", "employee_id": "EMP-0112", "is_honeytoken": True}
    ]

    # Assign credentials to random customers (or standard ones as employees)
    customer_nodes = [c["id"] for c in customers]
    for cred in credentials:
        # Choose a customer to associate this credential node with
        # To make it realistic, we attach employee credentials to customer nodes representing internal employees
        cred["owner_customer_id"] = random.choice(customer_nodes)

    insert_creds_query = """
    UNWIND $batch as cred
    MATCH (c:Customer {id: cred.owner_customer_id})
    CREATE (e:EmployeeCredential {
        username: cred.username,
        role: cred.role,
        employee_id: cred.employee_id,
        is_honeytoken: cred.is_honeytoken,
        password_hash: "pbkdf2:sha256:260000$mock_hash"
    })
    CREATE (c)-[:HAS_CREDENTIAL]->(e)
    """
    neo4j_client.execute_query(insert_creds_query, {"batch": credentials})
    logger.info("Generated employee credentials.")

    logger.info("Synthetic banking ecosystem generation complete!")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NyxVault Deception Database Seeding Utility")
    parser.add_argument("--customers", type=int, default=100, help="Number of customers to generate")
    parser.add_argument("--accounts", type=int, default=300, help="Number of accounts to generate")
    parser.add_argument("--transactions", type=int, default=2000, help="Number of transactions to generate")
    args = parser.parse_args()

    generate_synthetic_data(
        num_customers=args.customers,
        num_accounts=args.accounts,
        num_transactions=args.transactions
    )
