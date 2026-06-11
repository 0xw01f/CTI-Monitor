import logging
import re
from collections import defaultdict
from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import (
    Actor,
    ActorContact,
    GraphEntity,
    GraphRelation,
    Threat,
    ThreatEntity,
    ThreatLink,
)
from ..services.admin_auth import require_admin
from ..services.alerting import send_discord_threat_alert
from ..services.scorer import build_dedup_key

_HTML_TAG = re.compile(r"<[^>]+>")

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.post("/test")
async def test_alert(_: dict = Depends(require_admin)):
    """Send a test Discord alert to verify the webhook is configured correctly."""
    if not settings.discord_webhook_url:
        return {"ok": False, "detail": "DISCORD_WEBHOOK_URL is not configured"}

    class _FakeThreat:
        title = "⚠️ CTI Monitor — Test Alert"
        content = "This is a test notification to confirm your Discord webhook integration is working correctly."
        severity = "critical"
        type = "test"
        actor = "CTI-Monitor-Bot"
        country = None
        tags = ["test", "webhook"]
        url = None
        published_at = datetime.utcnow()

    await send_discord_threat_alert(_FakeThreat())
    return {"ok": True, "detail": "Test alert sent"}


@router.post("/reset-db")
def reset_db(
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    """Truncate all collected data (threats, actors, graph) while keeping sources intact."""
    try:
        db.query(GraphRelation).delete()
        db.query(ThreatEntity).delete()
        db.query(GraphEntity).delete()
        db.query(ThreatLink).delete()
        db.query(ActorContact).delete()
        db.query(Threat).delete()
        db.query(Actor).delete()
        db.commit()
        logger.info("Database reset: all collected data cleared.")
        return {"ok": True, "detail": "All collected data has been cleared. Sources kept intact."}
    except Exception as exc:
        db.rollback()
        logger.error(f"Reset DB failed: {exc}")
        return {"ok": False, "detail": str(exc)}


@router.post("/deduplicate-threats")
def deduplicate_threats(
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    """Delete duplicate threats sharing the same dedup_key, keeping the highest-scored one."""
    try:
        # Only consider non-deleted threats for deduplication
        threats = db.query(Threat).filter(Threat.is_deleted == False).all()  # noqa: E712

        groups: dict[str, list[Threat]] = defaultdict(list)
        for t in threats:
            actor_clean = _HTML_TAG.sub("", t.actor or "").strip()
            key = build_dedup_key(t.title, actor_clean)
            groups[key].append(t)

        deleted = 0
        for group in groups.values():
            if len(group) <= 1:
                continue
            # Keep the threat with the highest score (earliest id as tiebreaker)
            keep = max(group, key=lambda t: (t.score or 0, -t.id))
            for t in group:
                if t.id != keep.id:
                    # Soft-delete so the dedup key persists and prevents re-insertion
                    t.is_deleted = True
                    deleted += 1

        db.commit()
        logger.info("Deduplication: soft-deleted %d duplicate threats.", deleted)
        return {"ok": True, "detail": f"Removed {deleted} duplicate threat{'s' if deleted != 1 else ''}."}
    except Exception as exc:
        db.rollback()
        logger.error(f"Deduplication failed: {exc}")
        return {"ok": False, "detail": str(exc)}
