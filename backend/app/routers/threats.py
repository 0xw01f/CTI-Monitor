from datetime import datetime, timedelta

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import String, func
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import Source, Threat
from ..services.admin_auth import get_optional_admin, require_admin
from ..services.identity import strip_tags
from ..services.scorer import check_noise
from ..services.screenshot import ensure_post_screenshot, evidence_exists

router = APIRouter(prefix="/api/threats", tags=["threats"])


def _parse_iso(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        return None


def _noise_candidate(t: Threat) -> bool:
    text = f"{t.title or ''} {t.content or ''}".lower()
    if check_noise(t.title or "", t.content or "", t.actor or "").get("is_noise"):
        return True
    if (t.score or 0) < 30:
        return True
    if (t.type or "") == "other" and (t.score or 0) < 45:
        return True
    for term in ("mailer", "sms sender", "spoof sender", "verified account", "aged account", "vcc", "proxies"):
        if term in text:
            return True
    return False


def _to_dict(t: Threat, detailed: bool = False, force_screenshot: bool = False) -> dict:
    d = {
        "id": t.id,
        "title": t.title,
        "type": t.type,
        "severity": t.severity,
        "score": t.score,
        "actor": strip_tags(t.actor),
        "target": t.target,
        "country": t.country,
        "victim_origin": {
            "country": t.country or "Unknown",
            "method": t.victim_origin_method or "none",
            "confidence": float(t.victim_origin_confidence or 0.0),
            "evidence": t.victim_origin_evidence or "",
        },
        "tags": t.tags or [],
        "published_at": t.published_at.isoformat() if t.published_at else None,
        "fetched_at": t.fetched_at.isoformat() if t.fetched_at else None,
        "is_public": bool(t.is_public),
        "noise_candidate": _noise_candidate(t),
        # Include cached screenshot for card-view thumbnails without triggering a new capture
        "post_screenshot": t.post_screenshot_path if evidence_exists(t.post_screenshot_path) else None,
    }
    if detailed:
        cached = t.post_screenshot_path if evidence_exists(t.post_screenshot_path) else None
        screenshot_path = ensure_post_screenshot(
            t.url,
            t.id,
            actor=t.actor,
            source_name=t.source.name if t.source else None,
            force=force_screenshot or not cached,
        )
        if screenshot_path and t.post_screenshot_path != screenshot_path:
            t.post_screenshot_path = screenshot_path
        d["post_screenshot"] = screenshot_path or cached
        d["post_capture"] = {
            "text_length": len(t.full_post_text or ""),
            "html_length": len(t.full_post_html or ""),
        }
        d["extracted_links"] = [{"url": l.url, "domain": l.domain, "type": l.link_type} for l in t.links]
    return d


@router.get("/")
def list_threats(
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    type: str | None = None,
    severity: str | None = None,
    actor: str | None = None,
    source_id: int | None = None,
    country: str | None = None,
    tag: str | None = None,
    search: str | None = None,
    days: int | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    visibility: str | None = None,  # public | hidden | all (admin)
    noisy_only: bool = False,
    claims: dict | None = Depends(get_optional_admin),
):
    is_admin = bool(claims and claims.get("role") == "admin")
    q = db.query(Threat).join(Source).filter(Threat.is_deleted == False)  # noqa: E712

    if not is_admin or visibility == "public":
        q = q.filter(Threat.is_public.is_(True))
    elif visibility == "hidden":
        q = q.filter(Threat.is_public.is_(False))

    if type:
        q = q.filter(Threat.type == type)
    if severity:
        q = q.filter(Threat.severity == severity)
    if actor:
        q = q.filter(Threat.actor.ilike(f"%{actor}%"))
    if source_id:
        q = q.filter(Threat.source_id == source_id)
    if country:
        q = q.filter(Threat.country == country)
    if tag:
        q = q.filter(Threat.tags.cast(String).ilike(f'%"{tag}"%'))
    if search:
        q = q.filter(Threat.title.ilike(f"%{search}%") | Threat.content.ilike(f"%{search}%"))
    effective_date = func.coalesce(Threat.published_at, Threat.fetched_at)
    if days:
        q = q.filter(effective_date >= datetime.utcnow() - timedelta(days=days))
    start_dt = _parse_iso(start_date)
    end_dt = _parse_iso(end_date)
    if start_dt:
        q = q.filter(effective_date >= start_dt)
    if end_dt:
        q = q.filter(effective_date <= end_dt)
    if noisy_only:
        q = q.filter((Threat.score < 30) | ((Threat.type == "other") & (Threat.score < 45)))

    total = q.count()
    items = q.order_by(func.coalesce(Threat.published_at, Threat.fetched_at).desc()).offset(skip).limit(limit).all()
    return {"total": total, "items": [_to_dict(t) for t in items]}


@router.get("/{threat_id}")
def get_threat(
    threat_id: int,
    db: Session = Depends(get_db),
    refresh: bool = False,
    claims: dict | None = Depends(get_optional_admin),
):
    is_admin = bool(claims and claims.get("role") == "admin")
    t = db.query(Threat).filter(Threat.id == threat_id, Threat.is_deleted == False).first()  # noqa: E712
    if t and (not is_admin) and (not t.is_public):
        t = None
    if not t:
        raise HTTPException(status_code=404, detail="Not found")
    payload = _to_dict(t, detailed=True, force_screenshot=refresh)
    db.commit()
    return payload


@router.delete("/{threat_id}")
def delete_threat(
    threat_id: int,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    """Soft-delete a threat so it won't reappear on the next poll."""
    t = db.query(Threat).filter(Threat.id == threat_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Not found")
    t.is_deleted = True
    db.commit()
    return {"ok": True, "detail": f"Threat #{threat_id} deleted."}


@router.patch("/{threat_id}/visibility")
def set_public_visibility(
    threat_id: int,
    data: dict = Body(...),
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    t = db.query(Threat).filter(Threat.id == threat_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Not found")
    if "is_public" not in data:
        raise HTTPException(status_code=400, detail="Missing is_public")
    t.is_public = bool(data["is_public"])
    db.commit()
    return {"ok": True, "id": t.id, "is_public": bool(t.is_public)}


@router.post("/visibility/bulk")
def set_public_visibility_bulk(
    data: dict = Body(...),
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    ids = data.get("ids") or []
    if not isinstance(ids, list) or not ids:
        raise HTTPException(status_code=400, detail="ids must be a non-empty list")
    if "is_public" not in data:
        raise HTTPException(status_code=400, detail="Missing is_public")

    is_public = bool(data["is_public"])
    rows = db.query(Threat).filter(Threat.id.in_(ids)).all()
    for t in rows:
        t.is_public = is_public
    db.commit()
    return {"ok": True, "updated": len(rows), "is_public": is_public}


# ---------------------------------------------------------------------------
# X / Twitter post generation
# ---------------------------------------------------------------------------

import json as _json
import re as _re

_COUNTRY_PREFIX_RE = _re.compile(r"^\s*[\(\[]\s*[A-Z]{2}\s*[\)\]]\s*[-–:—]?\s*", _re.UNICODE)
_HTML_TAG_RE = _re.compile(r"<[^>]+>")
_MULTI_WS_RE = _re.compile(r"\s{2,}")


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


def _safe_content(t: Threat) -> str:
    """Return clean plain-text from the richest available source.

    Priority:
    1. full_post_text  — plain text already extracted by BeautifulSoup
    2. full_post_html  — raw HTML saved in DB; strip tags here
    3. content         — RSS summary (may also contain HTML)
    """
    candidates = [
        t.full_post_text or "",
        t.full_post_html or "",
        t.content or "",
    ]
    for raw in candidates:
        raw = raw.strip()
        if not raw:
            continue
        cleaned = _strip_html(raw)
        if len(cleaned) > 30 and _is_printable(cleaned):
            return cleaned[:3000]
    return ""


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


def _flag_emoji(iso: str) -> str:
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


def _fallback_tweet(t: Threat, flag: str, source_name: str, freshness: str) -> str:
    """Minimal tweet body when GPT is unavailable (hashtags appended by caller)."""
    title = _clean_title(t.title or "Unknown threat")[:80]
    severity = (t.severity or "unknown").upper()
    return f"{flag} {title}\n{severity} | {source_name} | {freshness}"


async def _gpt_tweet(
    t: Threat,
    flag: str,
    source_name: str,
    freshness: str,
    hashtags_str: str,
) -> str:
    """Ask GPT to write the complete tweet body, then append hashtags."""
    content_sample = _safe_content(t)

    if not settings.deepseek_api_key or not settings.deepseek_tweet_enabled:
        return _fallback_tweet(t, flag, source_name, freshness)

    # Reserve chars for the hashtag line (newline + hashtags)
    hashtag_reserve = len(hashtags_str) + 1
    body_limit = 280 - hashtag_reserve  # chars available for the tweet body

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
        f"Severity: {(t.severity or 'unknown').upper()}\n"
        f"Freshness: {freshness}\n"
        f"Type: {t.type or 'unknown'}\n"
        f"Tags: {', '.join(t.tags or [])}\n"
        f"Actor: {t.actor or 'unknown'}\n"
        f"Country: {t.country or 'unknown'}\n"
        f"Title: {_clean_title(t.title or '')}\n\n"
        f"Post content:\n{content_sample}"
    )

    try:
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
            data = _json.loads(resp.json()["choices"][0]["message"]["content"])
            body = str(data.get("tweet", "")).strip()
            if not body:
                raise ValueError("empty tweet")
            # Hard safety cap on the body (should not be needed if GPT follows rules)
            if len(body) > body_limit:
                # Find last sentence boundary within budget
                cutoff = body[:body_limit].rfind(". ")
                body = (body[: cutoff + 1] if cutoff > 20 else body[:body_limit]).rstrip()
            return body
    except Exception:
        return _fallback_tweet(t, flag, source_name, freshness)


@router.post("/{threat_id}/generate-x-post")
async def generate_x_post(
    threat_id: int,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    """Generate a ready-to-post X (Twitter) alert from a threat entry using GPT."""
    t = db.query(Threat).filter(Threat.id == threat_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Not found")

    source = db.query(Source).filter(Source.id == t.source_id).first()
    source_name = source.name if source else "Unknown"

    flag = _flag_emoji(t.country)
    freshness = _freshness(t.published_at)

    hashtags: set[str] = set(_X_TYPE_HASHTAGS.get(t.type or "", ["#databreach"]))
    for tag in t.tags or []:
        if tag in _X_TAG_HASHTAGS:
            hashtags.add(_X_TAG_HASHTAGS[tag])
    hashtags.add("#cti")
    hashtags_str = " ".join(sorted(hashtags))

    body = await _gpt_tweet(t, flag, source_name, freshness, hashtags_str)
    post_text = f"{body}\n{hashtags_str}"

    screenshot_url = t.post_screenshot_path if evidence_exists(t.post_screenshot_path) else None

    return {
        "ok": True,
        "text": post_text,
        "char_count": len(post_text),
        "screenshot_url": screenshot_url,
    }
