"""Runtime configuration, loaded from the environment (never hard-coded)."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database. Dev default is SQLite (runs anywhere); prod swaps to Postgres:
    #   DATABASE_URL=postgresql+asyncpg://user:pass@postgres:5432/watchfloor
    database_url: str = "sqlite+aiosqlite:///./dev.db"

    # Sessions
    session_cookie: str = "watchfloor_session"
    session_ttl_hours: int = 12          # absolute lifetime (~one shift)
    session_idle_minutes: int = 30       # inactivity timeout
    cookie_secure: bool = False          # True behind TLS in production

    # Auth policy (admin-changeable later; these are the defaults)
    otp_required: bool = False           # OTP can be enabled/disabled portal-wide
    password_min_length: int = 14
    lockout_attempts: int = 5
    lockout_minutes: int = 15

    # Initial admin (seeded once, on an empty user table)
    seed_admin_username: str = "admin"
    seed_admin_email: str = "admin@localhost"
    seed_admin_password: str = "changeme-admin-1234"

    # Web app (the core serves the front-end so cookies are same-origin)
    web_dir: str = "web"                 # holds portal.html + login.html
    mcp_soar_url: str = "http://mcp-soar:9000"
    mcp_roster_url: str = "http://mcp-roster:9000"
    mcp_detection_url: str = "http://mcp-detection:9000"

    # LLM gateway (unchanged)
    # Assistant — Claude via the Anthropic API
    anthropic_api_key: str = ""
    assistant_model: str = "claude-sonnet-5"
    assistant_max_tool_turns: int = 12
    assistant_verify_ssl: bool = False   # corp TLS-inspection proxy on this network
    soar_chat_bridge_url: str = "http://mcp-soar-chat:9011"

    litellm_base_url: str = "http://litellm:4000"
    llm_api_key: str = "change-me"
    llm_model: str = "soc-default"


settings = Settings()
