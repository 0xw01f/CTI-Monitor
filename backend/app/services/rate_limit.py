import time

from fastapi import Request
from starlette.responses import JSONResponse


class InMemoryRateLimiter:
    """Simple per-IP rate limiter (in-memory; resets on process restart)."""

    def __init__(self, max_requests: int = 120, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = window_seconds
        self._store: dict[str, list[float]] = {}

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        timestamps = self._store.get(key, [])
        timestamps = [t for t in timestamps if now - t < self.window]
        if len(timestamps) >= self.max_requests:
            self._store[key] = timestamps
            return False
        timestamps.append(now)
        self._store[key] = timestamps
        return True


_limiter = InMemoryRateLimiter()


async def rate_limit_middleware(request: Request, call_next):
    """Return 429 when a single IP exceeds 120 req/min."""
    if request.url.path == "/api/health":
        return await call_next(request)

    client_ip = request.client.host if request.client else "unknown"
    if not _limiter.is_allowed(client_ip):
        return JSONResponse(
            {"detail": "Rate limit exceeded — slow down."},
            status_code=429,
        )
    return await call_next(request)
