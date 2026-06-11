"""
One-shot script: publish the first N existing threats to Bluesky.

Run from the repo root (or inside the backend container):

    docker compose exec backend python scripts/publish_existing_to_bluesky.py --limit 3

Requires BLUESKY_ENABLED=true and valid BLUESKY_HANDLE / BLUESKY_APP_PASSWORD
in the environment (usually from your .env file).
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal, engine
from app.models import Base, SocialPost, Source, Threat
from app.services.social_poster import publish_threat_to_bluesky

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def get_unpublished_threats(db: Session, limit: int = 3):
    """Return the N most recent threats not already published on Bluesky."""
    subquery = (
        db.query(SocialPost.threat_id).filter(SocialPost.platform == "bluesky").filter(SocialPost.status == "published")
    )
    return (
        db.query(Threat)
        .filter(~Threat.id.in_(subquery))
        .filter(Threat.is_deleted.is_(False))
        .order_by(Threat.published_at.desc().nullslast())
        .limit(limit)
        .all()
    )


async def main(limit: int):
    if not settings.bluesky_enabled:
        logger.error("BLUESKY_ENABLED is not true. Set it in your .env and restart.")
        sys.exit(1)
    if not settings.bluesky_handle or not settings.bluesky_app_password:
        logger.error("BLUESKY_HANDLE and BLUESKY_APP_PASSWORD must be configured.")
        sys.exit(1)

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        threats = get_unpublished_threats(db, limit)
        if not threats:
            logger.info("No unpublished threats found.")
            return

        logger.info("Found %d unpublished threat(s).", len(threats))

        for threat in threats:
            source = db.query(Source).filter(Source.id == threat.source_id).first()
            source_name = source.name if source else "Unknown"

            logger.info(
                "Publishing threat #%d: %s",
                threat.id,
                (threat.title or "Untitled")[:60],
            )

            result = await publish_threat_to_bluesky(threat, source_name)

            social = SocialPost(
                threat_id=threat.id,
                platform="bluesky",
                post_url=result.get("post_url"),
                status="published" if result["ok"] else "failed",
                detail=result.get("detail"),
            )
            db.add(social)
            db.commit()

            if result["ok"]:
                logger.info("✅ Published: %s", result.get("post_url"))
            else:
                logger.error("❌ Failed: %s", result.get("detail"))

    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Publish existing threats to Bluesky")
    parser.add_argument("--limit", type=int, default=3, help="Number of threats to publish")
    args = parser.parse_args()
    asyncio.run(main(args.limit))
