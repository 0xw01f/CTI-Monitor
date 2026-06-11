"""
Social media auto-poster.

Currently supports Bluesky (AT Protocol). X/Twitter can be added later.
"""

import json
import logging
import re
from datetime import datetime
from typing import TYPE_CHECKING

import httpx
from atproto import Client
from atproto.exceptions import AtProtocolError
from starlette.concurrency import run_in_threadpool

from ..config import settings

if TYPE_CHECKING:
    from ..models import Threat

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Text generation helpers
# ---------------------------------------------------------------------------

_COUNTRY_PREFIX_RE = re.compile(r"^\s*[\(\[]\s*[A-Z]{2}\s*[\)\]]\s*[-–:—]?\s*", re.UNICODE)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_MULTI_WS_RE = re.compile(r"\s{2,}")

_X_TYPE_HASHTAGS: dict[str, list[str]] = {
    "database": ["#databreach"],
    "credentials": ["#databreach", "#credentials"],
    "stealer_logs": ["#infostealer"],
    "access": ["#initialaccess"],
    "source_code": ["#databreach"],
}

_X_TAG_HASHTAGS: dict[str, str] = {
    "ransomware": "#ransomware",
    "healthcare": "#healthcare",
    "finance": "#finance",
    "government": "#government",
}


def _clean_title(title: str) -> str:
    return _COUNTRY_PREFIX_RE.sub("", title).strip()


def _strip_html(text: str) -> str:
    text = _HTML_TAG_RE.sub(" ", text)
    text = _MULTI_WS_RE.sub(" ", text)
    return text.strip()


def _is_printable(text: str) -> bool:
    sample = text[:300]
    ratio = sum(1 for c in sample if c.isprintable() or c in "\n\r\t") / max(len(sample), 1)
    return ratio > 0.85


def _safe_content(threat: "Threat") -> str:
    """Return clean plain-text from the richest available source."""
    candidates = [
        threat.full_post_text or "",
        threat.full_post_html or "",
        threat.content or "",
    ]
    for raw in candidates:
        raw = raw.strip()
        if not raw:
            continue
        cleaned = _strip_html(raw)
        if len(cleaned) > 30 and _is_printable(cleaned):
            return cleaned[:3000]
    return ""


def _flag_emoji(iso: str | None) -> str:
    iso = (iso or "").upper().strip()
    if len(iso) == 2 and iso.isalpha():
        return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in iso)
    return "🌐"


def _freshness(pub: datetime | None) -> str:
    if not pub:
        return "unknown"
    pub_naive = pub.replace(tzinfo=None) if getattr(pub, "tzinfo", None) else pub
    age_h = (datetime.utcnow() - pub_naive).total_seconds() / 3600
    if age_h < 1:
        return "<1h ago"
    if age_h < 24:
        return f"{int(age_h) + 1}h ago"
    if age_h < 48:
        return "1d ago"
    return f"{int(age_h // 24)}d ago"


def _fallback_tweet(threat: "Threat", flag: str, source_name: str, freshness: str) -> str:
    """Minimal tweet body when LLM is unavailable (hashtags appended by caller)."""
    title = _clean_title(threat.title or "Unknown threat")[:80]
    severity = (threat.severity or "unknown").upper()
    return f"{flag} {title}\n{severity} | {source_name} | {freshness}"


def _build_hashtags(threat: "Threat") -> str:
    hashtags: set[str] = set(_X_TYPE_HASHTAGS.get(threat.type or "", ["#databreach"]))
    for tag in threat.tags or []:
        if tag in _X_TAG_HASHTAGS:
            hashtags.add(_X_TAG_HASHTAGS[tag])
    hashtags.add("#cti")
    return " ".join(sorted(hashtags))


async def _llm_tweet_body(
    threat: "Threat",
    flag: str,
    source_name: str,
    freshness: str,
    hashtags_str: str,
) -> str:
    """Use DeepSeek to write the social post body."""
    content_sample = _safe_content(threat)

    hashtag_reserve = len(hashtags_str) + 1
    body_limit = 280 - hashtag_reserve

    system_prompt = (
        "You are a CTI analyst writing punchy, concise threat alerts for X (Twitter).\n"
        "Rules:\n"
        "- Write ONLY the tweet body (no hashtags — they are added separately).\n"
        f"- Stay under {body_limit} characters total.\n"
        "- Use hedged language: 'allegedly', 'reportedly', 'claimed'.\n"
        "- Be terse: abbreviate where natural (e.g. 'DB' not 'database', 'org' not 'organization').\n"
        "- Lead with the flag emoji and a short punchy headline, then 1-2 key detail lines.\n"
        "- Include the source name, severity, and freshness naturally — no rigid bullet labels.\n"
        "- Do NOT invent data not present in the post. If detail is unknown, omit it.\n"
        '- Respond ONLY with a JSON object: {"tweet": "<tweet body text>"}'
    )

    user_prompt = (
        f"Flag: {flag}\n"
        f"Source: {source_name}\n"
        f"Severity: {(threat.severity or 'unknown').upper()}\n"
        f"Freshness: {freshness}\n"
        f"Type: {threat.type or 'unknown'}\n"
        f"Tags: {', '.join(threat.tags or [])}\n"
        f"Actor: {threat.actor or 'unknown'}\n"
        f"Country: {threat.country or 'unknown'}\n"
        f"Title: {_clean_title(threat.title or '')}\n\n"
        f"Post content:\n{content_sample}"
    )

    async with httpx.AsyncClient(timeout=25.0) as client:
        resp = await client.post(
            f"{settings.deepseek_base_url.rstrip('/')}/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.deepseek_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": settings.deepseek_model,
                "temperature": 0.3,
                "max_tokens": 300,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            },
        )
        resp.raise_for_status()
        data = json.loads(resp.json()["choices"][0]["message"]["content"])
        body = str(data.get("tweet", "")).strip()
        if not body:
            raise ValueError("empty tweet")
        if len(body) > body_limit:
            cutoff = body[:body_limit].rfind(". ")
            body = (body[: cutoff + 1] if cutoff > 20 else body[:body_limit]).rstrip()
        return body


async def generate_threat_post_text(threat: "Threat", source_name: str = "Unknown") -> str:
    """Generate a ready-to-post social text (body + hashtags) for a threat."""
    flag = _flag_emoji(threat.country)
    freshness = _freshness(threat.published_at)
    hashtags_str = _build_hashtags(threat)

    if settings.deepseek_api_key and settings.deepseek_tweet_enabled:
        try:
            body = await _llm_tweet_body(threat, flag, source_name, freshness, hashtags_str)
        except Exception:
            body = _fallback_tweet(threat, flag, source_name, freshness)
    else:
        body = _fallback_tweet(threat, flag, source_name, freshness)

    return f"{body}\n{hashtags_str}"


# ---------------------------------------------------------------------------
# Bluesky publisher
# ---------------------------------------------------------------------------


def _build_post_url(handle: str, uri: str) -> str:
    """Build a human-readable Bluesky post URL from an at:// URI."""
    try:
        rkey = uri.split("/")[-1]
        return f"https://bsky.app/profile/{handle}/post/{rkey}"
    except Exception:
        return f"https://bsky.app/profile/{handle}"


def _publish_bluesky_sync(text: str, image_path: str | None, handle: str, app_password: str) -> dict:
    """Synchronous Bluesky publish helper (runs in threadpool)."""
    client = Client()
    client.login(handle, app_password)

    image_bytes = None
    if image_path:
        try:
            with open(image_path, "rb") as f:
                image_bytes = f.read()
        except Exception as exc:
            logger.warning("Could not read screenshot for Bluesky post: %s", exc)

    if image_bytes:
        upload = client.upload_blob(image_bytes)
        embed = {
            "$type": "app.bsky.embed.images#main",
            "images": [
                {
                    "alt": "Threat evidence screenshot",
                    "image": upload.blob,
                }
            ],
        }
        response = client.send_post(text=text, embed=embed)
    else:
        response = client.send_post(text=text)

    post_url = _build_post_url(handle, response.uri)
    return {"ok": True, "post_url": post_url, "detail": "Published"}


async def publish_to_bluesky(text: str, image_path: str | None = None) -> dict:
    """
    Publish a text post to Bluesky.

    Returns {"ok": bool, "post_url": str | None, "detail": str}.
    """
    if not settings.bluesky_enabled:
        return {"ok": False, "post_url": None, "detail": "Bluesky is not enabled"}
    if not settings.bluesky_handle or not settings.bluesky_app_password:
        return {"ok": False, "post_url": None, "detail": "Bluesky credentials not configured"}

    try:
        return await run_in_threadpool(
            _publish_bluesky_sync,
            text,
            image_path,
            settings.bluesky_handle,
            settings.bluesky_app_password,
        )
    except AtProtocolError as exc:
        logger.warning("Bluesky publish failed: %s", exc)
        return {"ok": False, "post_url": None, "detail": f"Bluesky error: {exc}"}
    except Exception as exc:
        logger.warning("Bluesky publish failed: %s", exc)
        return {"ok": False, "post_url": None, "detail": f"Unexpected error: {exc}"}


async def publish_threat_to_bluesky(threat: "Threat", source_name: str = "Unknown") -> dict:
    """Generate and publish a Bluesky post for a threat. Returns the publish result."""
    text = await generate_threat_post_text(threat, source_name)
    screenshot_path = None
    if threat.post_screenshot_path:
        from .screenshot import evidence_exists

        if evidence_exists(threat.post_screenshot_path):
            screenshot_path = threat.post_screenshot_path
    return await publish_to_bluesky(text, image_path=screenshot_path)
