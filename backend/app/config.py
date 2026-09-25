"""Application configuration for AegisAI."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Store AegisAI configuration loaded from environment variables."""

    app_name: str = "AegisAI"
    app_env: str = "development"
    debug: bool = False

    secret_key: str = "development-only-change-me"

    max_input_length: int = 8000
    max_output_length: int = 12000

    default_block_threshold: int = 70
    default_warn_threshold: int = 40

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return a cached application settings instance."""

    return Settings()


settings = get_settings()