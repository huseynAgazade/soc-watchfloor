"""Runtime configuration, loaded from the environment (never hard-coded)."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database. Dev default is SQLite (runs anywhere); prod swaps to Postgres:
    #   DATABASE_URL=postgresql+asyncpg://user:pass@postgres:5432/watchfloor
    database_url: str = "sqlite+aiosqlite:///./dev.db"

    # Organisation — reporting periods and "today" are resolved in this zone
    org_timezone: str = "Asia/Dubai"
    max_period_days: int = 92            # longest reporting window a caller may request

    # Sessions
    session_cookie: str = "watchfloor_session"
    session_ttl_hours: int = 12          # absolute lifetime (~one shift)
    session_idle_minutes: int = 30       # inactivity timeout
    cookie_secure: bool = False          # True behind TLS in production

    # HTTPS and browser security (app/security/web_guard.py)
    force_https: bool = False            # redirect plain HTTP to HTTPS
    https_port: int = 443                # port used in that redirect
    hsts_enabled: bool = False           # only with a certificate browsers trust: HSTS pins HTTPS for a year
    trust_proxy_headers: bool = False    # honour X-Forwarded-Proto / X-Forwarded-For from a reverse proxy
    public_site: bool = False            # False keeps search engines out (robots.txt, noindex)
    public_base_url: str = ""            # e.g. https://watchfloor.example.com, for canonical and preview URLs

    # Sign-in throttling per client address (form spam, password spraying)
    login_ip_attempts: int = 20          # failed sign-ins from one address...
    login_ip_window_seconds: int = 600   # ...within this window, then 429 until the oldest expires

    # First-party usage statistics: page views per page and role, only with the viewer's consent
    analytics_enabled: bool = True

    # Auth policy (admin-changeable later; these are the defaults)
    otp_required: bool = False           # OTP can be enabled/disabled portal-wide
    password_min_length: int = 14
    lockout_attempts: int = 5
    lockout_minutes: int = 15

    # Initial admin (seeded once, on an empty user table). There is no default
    # password: leave it empty and a random one is generated, printed once to the
    # log, and must be changed at first sign-in.
    seed_admin_username: str = "admin"
    seed_admin_email: str = "admin@localhost"
    seed_admin_password: str = ""

    # Web app (the core serves the front-end so cookies are same-origin)
    web_dir: str = "web"                 # holds portal.html + login.html
    mcp_soar_url: str = "http://mcp-soar:9000"
    mcp_roster_url: str = "http://mcp-roster:9000"
    mcp_detection_url: str = "http://mcp-detection:9000"
    soar_splunk_server: str = "soc_soar"   # restsoar soar_server for $soar_containers$

    # Assistant — Claude via the Anthropic API
    anthropic_api_key: str = ""
    assistant_model: str = "claude-sonnet-5"
    assistant_verify_ssl: bool = False   # corp TLS-inspection proxy on this network
    soar_chat_bridge_url: str = "http://mcp-soar-chat:9011"

    # Assistant limits. Per question: size, history, model round-trips, tool
    # executions, result size, output and wall clock. Per user: request rate and
    # one question at a time (held in process memory, i.e. per core worker).
    assistant_max_message_chars: int = 4000
    assistant_max_history_turns: int = 20
    assistant_max_history_chars: int = 24000
    assistant_max_tool_turns: int = 8
    assistant_max_tool_calls: int = 12
    assistant_max_tool_result_chars: int = 8000
    assistant_max_output_tokens: int = 2048
    assistant_timeout_seconds: int = 120
    assistant_requests_per_minute: int = 6
    assistant_requests_per_day: int = 200
    # Saved conversations (private to each user)
    assistant_saved_chat_days: int = 90          # removed this long after their last question
    assistant_saved_chats_per_user: int = 100    # the oldest beyond this are removed
    assistant_saved_turn_chars: int = 200_000    # a bigger turn is kept without its result rows

    litellm_base_url: str = "http://litellm:4000"
    llm_api_key: str = "change-me"
    llm_model: str = "soc-default"


settings = Settings()
