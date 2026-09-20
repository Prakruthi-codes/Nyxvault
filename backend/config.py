from pydantic_settings import BaseSettings
from pydantic import Field

class Settings(BaseSettings):
    NEO4J_URI: str = "neo4j+s://5ec541f5.databases.neo4j.io"
    # Use Field with validation_alias so that either NEO4J_USER or NEO4J_USERNAME works
    NEO4J_USER: str = Field(default="neo4j", validation_alias="NEO4J_USERNAME")
    NEO4J_PASSWORD: str = ""
    
    # Restoring required simulation settings that were missing
    ENVIRONMENT: str = "development"
    MUTATION_INTERVAL_MINUTES: int = 3
    SIMULATION_INTERVAL_SECONDS: int = 10
    ALERT_THRESHOLD: float = 0.85

    class Config:
        env_file = ".env"

settings = Settings()
