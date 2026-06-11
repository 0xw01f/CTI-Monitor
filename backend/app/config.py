from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql://cti:ctipass@localhost:5432/ctimonitor"
    poll_interval: int = 1200  # seconds (base ~20 min, randomised with poll_jitter)
    bootstrap_source_name: str = "primary-feed"
    bootstrap_source_url: str = ""

    # OPSEC: outbound proxy for all source requests. Either proxy_url or tor must be set.
    proxy_url: str = ""  # http://user:pass@host:port or socks5://host:port
    use_tor: bool = False
    tor_proxy_url: str = "socks5://tor:9050"

    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str = "https://api.openai.com/v1"
    openai_temperature: float = 0.1
    openai_top_p: float = 1.0
    openai_max_tokens: int = 120
    openai_timeout_seconds: float = 20.0
    openai_origin_enabled: bool = True

    # Kimi K2 classifier
    kimi_api_key: str = ""

    # Discord webhook for alerts (critical/high threats)
    discord_webhook_url: str = ""
    # XenForo auth cookie value for authenticated RSS feeds (e.g. breached.st)
    breached_xf_user_cookie: str = ""

    # Admin authentication (for private admin dashboard)
    admin_auth_enabled: bool = True
    admin_username: str = "admin"
    # Use ADMIN_PASSWORD_HASH (scrypt$N$r$p$salt_b64$hash_b64).
    # Plain-text passwords are NOT supported.
    admin_password_hash: str = ""
    admin_token_secret: str = ""
    admin_token_ttl_minutes: int = 720
    # Optional TOTP seed (base32). If set, login requires totp_code.
    admin_totp_secret: str = ""

    # CORS: comma-separated list of allowed origins. "*" means all (dev only).
    cors_allowed_origins: str = "*"

    # Disable SSL certificate verification for HTTP fetches (INSECURE — use only
    # in isolated environments or with Tor). Default False.
    insecure_ssl: bool = False

    # Scheduler: poll every ~poll_interval seconds ± poll_jitter seconds
    poll_jitter: int = 600  # ±10 min → range 10–30 min when interval=1200

    class Config:
        env_file = ".env"


settings = Settings()
