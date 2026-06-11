from datetime import datetime, timedelta

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import String, func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import SocialPost, Source, Threat
from ..services.admin_auth import get_optional_admin, require_admin
from ..services.identity import strip_tags
from ..services.scorer import check_noise
from ..services.screenshot import ensure_post_screenshot, evidence_exists
from ..services.social_poster import generate_threat_post_text, publish_threat_to_bluesky

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

    post_text = await generate_threat_post_text(t, source_name)
    screenshot_url = t.post_screenshot_path if evidence_exists(t.post_screenshot_path) else None

    return {
        "ok": True,
        "text": post_text,
        "char_count": len(post_text),
        "screenshot_url": screenshot_url,
    }


@router.post("/{threat_id}/publish-bluesky")
async def publish_bluesky(
    threat_id: int,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    """Generate and publish a Bluesky alert for a threat entry."""
    t = db.query(Threat).filter(Threat.id == threat_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Not found")

    source = db.query(Source).filter(Source.id == t.source_id).first()
    source_name = source.name if source else "Unknown"

    result = await publish_threat_to_bluesky(t, source_name)

    social = SocialPost(
        threat_id=t.id,
        platform="bluesky",
        post_url=result.get("post_url"),
        status="published" if result["ok"] else "failed",
        detail=result.get("detail"),
    )
    db.add(social)
    db.commit()

    if not result["ok"]:
        raise HTTPException(status_code=502, detail=result["detail"])

    return {
        "ok": True,
        "post_url": result["post_url"],
        "text": result.get("text", ""),
        "char_count": len(result.get("text", "")),
    }
