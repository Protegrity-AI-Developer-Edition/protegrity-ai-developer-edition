"""Configuration loader for the Protegrity-Composio secure bridge demo."""
from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv
    _env = Path(__file__).resolve().parent / ".env"
    load_dotenv(_env if _env.exists() else None, override=True)
except ImportError:
    pass


@dataclass(frozen=True)
class Config:
    # Protegrity
    dev_email: str
    dev_password: str
    dev_api_key: str
    classify_url: str
    sgr_url: str
    detokenize_url: str
    # Composio
    composio_api_key: str
    # OpenAI
    openai_api_key: str
    openai_model: str


def load_config() -> Config:
    required = ["DEV_EDITION_EMAIL", "DEV_EDITION_PASSWORD", "DEV_EDITION_API_KEY",
                "COMPOSIO_API_KEY", "OPENAI_API_KEY"]
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        raise EnvironmentError(f"Missing env vars: {', '.join(missing)}. Check .env file.")
    return Config(
        dev_email=os.environ["DEV_EDITION_EMAIL"],
        dev_password=os.environ["DEV_EDITION_PASSWORD"],
        dev_api_key=os.environ["DEV_EDITION_API_KEY"],
        classify_url=os.environ.get("CLASSIFY_URL", "http://localhost:8580/pty/data-discovery/v1.1/classify"),
        sgr_url=os.environ.get("SGR_URL", "http://localhost:8581/pty/semantic-guardrail/v1.1/conversations/messages/scan"),
        detokenize_url=os.environ.get("DETOKENIZE_URL", "http://localhost:8580/pty/data-protection/v1.1/detokenize"),
        composio_api_key=os.environ["COMPOSIO_API_KEY"],
        openai_api_key=os.environ["OPENAI_API_KEY"],
        openai_model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
    )
