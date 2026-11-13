"""Environment-based configuration. Every setting is overridable with an ARGUS_ prefixed env var."""
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARGUS_", env_file=".env", extra="ignore")

    env: str = "local"  # local | production
    database_url: str = f"sqlite:///{BACKEND_ROOT / 'argus.db'}"
    storage_dir: Path = BACKEND_ROOT / "storage"
    data_dir: Path = BACKEND_ROOT / "data"

    # Auth: when set, every /api request must carry X-API-Key. Mandatory when env=production.
    api_key: str | None = None
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    rate_limit_per_minute: int = 240

    max_upload_bytes: int = 25 * 1024 * 1024
    max_evidence_per_investigation: int = 50

    # Network behaviour. ARGUS never touches the network unless explicitly allowed.
    allow_network_fetch: bool = False   # live fetch of submitted URLs (SSRF-guarded)
    intel_offline: bool = True          # use bundled sample intelligence only
    fetch_timeout_seconds: float = 6.0
    fetch_max_redirects: int = 5
    fetch_max_bytes: int = 512 * 1024

    # Optional threat-intel keys (server side only, never returned by the API or logged)
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    otx_api_key: str | None = None
    intel_cache_ttl_seconds: int = 24 * 3600

    # Optional LLM narrative provider: none | openai_compatible | anthropic
    llm_provider: str = "none"
    llm_base_url: str = "http://localhost:11434/v1"
    llm_model: str = "llama3.1"
    llm_api_key: str | None = None

    run_inline: bool = False  # run the pipeline synchronously (tests)
    workers: int = 2          # investigations analysed concurrently; others queue


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.storage_dir.mkdir(parents=True, exist_ok=True)
    if s.env == "production" and not s.api_key:
        raise RuntimeError("ARGUS_API_KEY is required when ARGUS_ENV=production")
    return s
