from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    vector_database_url: str = "postgresql://catalog:catalog@vector-db:5432/catalog"
    security_database_url: str = (
        "postgresql://vulnerability_app:vulnerability_demo@security-db:5432/vulnerabilities"
    )
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-haiku-4-5-20251001"
    embedding_model: str = "BAAI/bge-small-en-v1.5"
    embedding_dimensions: int = 384
    query_timeout_ms: int = 5000
    query_row_cap: int = 100
    demo_mode: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
