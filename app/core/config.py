"""Application settings, loaded from environment variables and an optional .env file.

Configuration is validated once at startup. A typo such as INJECTION_BLOCK_THRESHOLD=7
(instead of 0.7) stops the app from booting, rather than silently switching the
guardrails off. That's the "fail closed" principle applied to configuration.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        # `OPENAI_API_KEY=` (blank, as in .env.example) means "not set", not "".
        env_ignore_empty=True,
        extra="ignore",
    )

    app_name: str = "ai-app-security-gateway"
    environment: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # --- LLM provider -------------------------------------------------------
    # SecretStr hides the value in repr/str/logs; read it with .get_secret_value().
    openai_api_key: SecretStr | None = None
    openai_model: str | None = None
    openai_timeout_seconds: float = Field(default=30.0, gt=0, le=300)

    # --- Langfuse tracing ---------------------------------------------------
    langfuse_public_key: str | None = None
    langfuse_secret_key: SecretStr | None = None
    langfuse_host: str = "https://cloud.langfuse.com"

    # --- Guardrails ---------------------------------------------------------
    injection_block_threshold: float = Field(default=0.7, gt=0, le=1)
    injection_medium_threshold: float = Field(default=0.4, gt=0, le=1)
    output_leak_threshold: float = Field(default=0.2, gt=0, le=1)
    # Huge prompts cost money and slow every regex down: reject them early.
    max_prompt_chars: int = Field(default=20_000, gt=0, le=500_000)
    restore_pii_in_response: bool = True
    # Include rule ids and scores in 400 responses. Handy while developing, but in
    # production it tells attackers exactly which rule to work around.
    expose_violation_details: bool = False

    @model_validator(mode="after")
    def _check_consistency(self) -> Self:
        if self.injection_medium_threshold > self.injection_block_threshold:
            raise ValueError("injection_medium_threshold must not exceed injection_block_threshold")
        if self.environment == "production":
            missing = [
                name
                for name, value in (
                    ("OPENAI_API_KEY", self.openai_api_key),
                    ("OPENAI_MODEL", self.openai_model),
                )
                if not value
            ]
            if missing:
                raise ValueError(f"production requires: {', '.join(missing)}")
            if self.expose_violation_details:
                raise ValueError("expose_violation_details must be false in production")
        return self

    @property
    def langfuse_enabled(self) -> bool:
        return bool(self.langfuse_public_key and self.langfuse_secret_key)


@lru_cache
def get_settings() -> Settings:
    """Load settings once and reuse them (FastAPI injects this as a dependency)."""
    return Settings()
