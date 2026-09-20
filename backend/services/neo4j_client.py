import logging
from typing import Dict, Any, List
from neo4j import GraphDatabase, Driver
from config import settings

logger = logging.getLogger("nyxvault.neo4j")
logging.basicConfig(level=logging.INFO)

class Neo4jClient:
    def __init__(self):
        self.uri = settings.NEO4J_URI
        self.user = settings.NEO4J_USER
        self.password = settings.NEO4J_PASSWORD
        self._driver: Driver = None
        self.connect()

    def connect(self):
        try:
            logger.info(f"Connecting to Neo4j at {self.uri}")
            self._driver = GraphDatabase.driver(
                self.uri, 
                auth=(self.user, self.password)
            )
            self._driver.verify_connectivity()
            logger.info("Successfully connected to Neo4j")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            self._driver = None

    def close(self):
        if self._driver:
            self._driver.close()
            logger.info("Neo4j driver connection closed")

    def verify_connectivity(self) -> bool:
        if not self._driver:
            self.connect()
        if not self._driver:
            return False
        try:
            self._driver.verify_connectivity()
            return True
        except Exception as e:
            logger.error(f"Connectivity check failed: {e}")
            return False

    def execute_query(self, query: str, parameters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Executes a Cypher query and returns the results as a list of dicts.
        """
        if not self._driver:
            self.connect()
        if not self._driver:
            raise ConnectionError("Neo4j driver is not initialized")

        parameters = parameters or {}
        try:
            with self._driver.session() as session:
                result = session.run(query, parameters)
                return [record.data() for record in result]
        except Exception as e:
            logger.error(f"Error executing Cypher query: {e}\nQuery: {query}")
            raise e

    def execute_write(self, cypher_fn, *args, **kwargs):
        """
        Runs a write transaction function in a session.
        """
        if not self._driver:
            self.connect()
        if not self._driver:
            raise ConnectionError("Neo4j driver is not initialized")

        try:
            with self._driver.session() as session:
                return session.execute_write(cypher_fn, *args, **kwargs)
        except Exception as e:
            logger.error(f"Error in write transaction: {e}")
            raise e

# Global client instance
neo4j_client = Neo4jClient()
