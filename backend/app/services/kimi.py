"""
DeepSeek post classifier (replaces Kimi K2).

classify_post(text) → {"type": str, "confidence": float}
Types: database | access | stealer | combo | other
"""

import json
import logging
import re

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

_FALLBACK: dict = {"type": "other", "confidence": 0.0}
_VALID_TYPES = {"database", "access", "stealer", "combo", "other"}

_SYSTEM = "You classify cyber threat posts."
_USER_TMPL = (
    "Classify this post into one category:\n"
    "[database, access, stealer, combo, other]\n\n"
    'Return ONLY JSON:\n{{"type": "...", "confidence": 0-1}}\n\n'
    "Post:\n{text}"
)


def _extract_json(raw: str) -> dict | None:
    raw = (raw or "").strip()
    try:
        return json.loads(raw)
    except Exception:
        pass
    m = re.search(r"\{[^}]+\}", raw)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return None


async def classify_post(text: str) -> dict:
    if not settings.deepseek_api_key or not settings.deepseek_classify_enabled:
        return _FALLBACK

    payload = {
        "model": settings.deepseek_model,
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": _USER_TMPL.format(text=text[:4000])},
        ],
        "temperature": 0,
        "max_tokens": 20,
    }
    headers = {
        "Authorization": f"Bearer {settings.deepseek_api_key}",
        "Content-Type": "application/json",
    }

    for attempt in range(3):  # 1 attempt + 2 retries
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{settings.deepseek_base_url.rstrip('/')}/chat/completions",
                    headers=headers,
                    json=payload,
                )
                # 401/403 = bad key — no point retrying
                if resp.status_code in (401, 403):
                    logger.warning(
                        "DeepSeek classify: auth error %d — check DEEPSEEK_API_KEY in .env",
                        resp.status_code,
                    )
                    return _FALLBACK
                resp.raise_for_status()
                data = resp.json()
        except (httpx.TimeoutException, httpx.HTTPStatusError, httpx.RequestError) as exc:
            logger.warning("DeepSeek classify attempt %d failed: %s", attempt + 1, exc)
            if attempt < 2:
                continue
            return _FALLBACK

        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        parsed = _extract_json(content)
        if not parsed:
            return _FALLBACK

        result_type = str(parsed.get("type", "other")).lower().strip()
        if result_type not in _VALID_TYPES:
            result_type = "other"

        try:
            confidence = float(parsed.get("confidence", 0.5))
        except Exception:
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))

        return {"type": result_type, "confidence": confidence}

    return _FALLBACK
