from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel
from pydantic_settings import BaseSettings


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080


class UpstreamConfig(BaseModel):
    base_url: str = "https://api.anthropic.com"
    timeout_seconds: int = 300


class SanitizationConfig(BaseModel):
    enabled: bool = True
    entities: list[str] = [
        "PERSON",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
        "IBAN_CODE",
        "SE_PERSONNUMMER",
        "SE_SAMORDNINGSNUMMER",
        "SE_ORGANIZATION_NUMBER",
        "SE_POSTAL_CODE",
        "LOCATION",
    ]
    score_threshold: float = 0.5
    languages: list[str] = ["en", "sv"]


class AuditConfig(BaseModel):
    enabled: bool = True
    log_file: str = "audit.jsonl"
    log_original_values: bool = False


class Settings(BaseSettings):
    server: ServerConfig = ServerConfig()
    upstream: UpstreamConfig = UpstreamConfig()
    sanitization: SanitizationConfig = SanitizationConfig()
    allowlist: list[str] = ["Claude", "Anthropic"]
    audit: AuditConfig = AuditConfig()

    model_config = {"env_prefix": "SANITIZER_"}


def load_settings(config_path: str | Path = "config.yaml") -> Settings:
    """Load settings from config.yaml, falling back to defaults."""
    path = Path(config_path)
    if path.exists():
        with open(path) as f:
            data: dict[str, Any] = yaml.safe_load(f) or {}
        return Settings(**data)
    return Settings()
