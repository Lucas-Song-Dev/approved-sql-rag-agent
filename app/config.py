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
    query_max_plan_cost: float = 10000
    query_max_plan_rows: int = 100000
    workos_api_key: str | None = None
    workos_client_id: str | None = None
    workos_cookie_password: str | None = None
    workos_redirect_uri: str = "http://localhost:8000/auth/callback"
    cookie_secure: bool = False
    allowed_origin: str = "http://localhost:8000"
    chat_rate_limit: int = 20
    chat_rate_window_seconds: int = 60


@lru_cache
def get_settings() -> Settings:
    return Settings()
