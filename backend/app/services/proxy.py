import logging
import socket
from urllib.parse import urlparse

from ..config import settings

logger = logging.getLogger(__name__)

# Cached result so we don't TCP-healthcheck on every single request.
_cached_proxy: str | None = None


def _tor_reachable() -> bool:
    """Quick TCP connect to the Tor SOCKS port (1 s timeout)."""
    try:
        parsed = urlparse(settings.tor_proxy_url)
        host = parsed.hostname or "tor"
        port = parsed.port or 9050
        with socket.create_connection((host, port), timeout=1):
            return True
    except Exception:
        return False


def get_outbound_proxy() -> str | None:
    """Return the proxy URL that must be used for every outbound source request.

    Logic:
      - If USE_TOR is enabled and Tor responds → Tor proxy.
      - If Tor is down (or USE_TOR is false) and PROXY_URL is set → PROXY_URL.
      - Otherwise → None (caller must block the request).
    """
    global _cached_proxy

    if _cached_proxy is not None:
        return _cached_proxy

    if settings.use_tor:
        if _tor_reachable():
            _cached_proxy = settings.tor_proxy_url
            logger.info("OPSEC: using Tor proxy (%s)", _cached_proxy)
            return _cached_proxy
        logger.warning("OPSEC: Tor is unreachable (%s)", settings.tor_proxy_url)

    if settings.proxy_url:
        _cached_proxy = settings.proxy_url
        logger.info("OPSEC: using fallback proxy (%s)", _cached_proxy)
        return _cached_proxy

    return None


def require_proxy(operation: str = "outbound request") -> str:
    """Return the active proxy URL or raise RuntimeError.

    By default CTI Monitor refuses to perform any source request without a
    proxy to avoid leaking the host IP. Set USE_TOR=true and/or PROXY_URL.
    """
    proxy = get_outbound_proxy()
    if not proxy:
        raise RuntimeError(
            f"OPSEC: {operation} blocked — no outbound proxy configured. "
            "Set USE_TOR=true (Tor container) and/or PROXY_URL in your .env."
        )
    return proxy
