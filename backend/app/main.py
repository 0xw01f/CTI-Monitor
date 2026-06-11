import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .config import settings
from .database import SessionLocal, engine
from .models import (  # noqa: F401 — ensures new tables are created
    ActorRelation,
    ActorSource,
    Base,
    Source,
)
from .routers import actors, admin_auth, alerts, dashboard, sources, threats
from .services.migrations import ensure_runtime_migrations
from .services.poller import poll_all_sources
from .services.rate_limit import rate_limit_middleware

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler(timezone="UTC")

DEFAULT_SOURCES = [
    {
        "name": settings.bootstrap_source_name,
        "url": settings.bootstrap_source_url,
        "type": "rss",
        "category": "forum",
        "fetch_interval": settings.poll_interval,
        "quality_score": 0.7,
    },
    # darkforums RSS — primary format
    {
        "name": "darkforums-fid10-rss",
        "url": "https://darkforums.su/syndication.php?fid=10",
        "type": "rss",
        "category": "leak_site",
        "fetch_interval": settings.poll_interval,
        "quality_score": 0.8,
    },
    # darkforums Atom — secondary format (same content, different serialisation;
    # fetch_rss already auto-derives this as a tier-2 fallback, but registering
    # it as its own source lets the scheduler poll it independently if needed)
    {
        "name": "darkforums-fid10-atom",
        "url": "https://darkforums.su/syndication.php?type=atom1.0&fid=10",
        "type": "atom",
        "category": "leak_site",
        "fetch_interval": settings.poll_interval,
        "quality_score": 0.8,
    },
    # darkforums RSS — additional leaks market section
    {
        "name": "darkforums-fid81-rss",
        "url": "https://darkforums.su/syndication.php?fid=81",
        "type": "rss",
        "category": "leak_site",
        "fetch_interval": settings.poll_interval,
        "quality_score": 0.8,
    },
    # spear.cx RSS sections (high spam density; filtered in poller)
    {
        "name": "spear-fid23-rss",
        "url": "https://spear.cx/syndication.php?fid=23",
        "type": "rss",
        "category": "leak_site",
        "fetch_interval": settings.poll_interval,
        "quality_score": 0.7,
    },
    {
        "name": "spear-fid53-rss",
        "url": "https://spear.cx/syndication.php?fid=53",
        "type": "rss",
        "category": "leak_site",
        "fetch_interval": settings.poll_interval,
        "quality_score": 0.7,
    },
    # breached.st RSS (requires authenticated xf_user cookie)
    {
        "name": "breached-databases-rss",
        "url": "https://breached.st/forums/databases.14/index.rss",
        "type": "rss",
        "category": "leak_site",
        "fetch_interval": settings.poll_interval,
        "quality_score": 0.9,
    },
    # umbra.st — fid=58 consistently returns 504 (feed broken server-side;
    # the site itself is reachable).  Kept here so it can be re-enabled once
    # the correct fid is known.  Set active=False via the API or remove if
    # confirmed dead.
    {
        "name": "umbra-fid58",
        "url": "https://umbra.st/syndication.php?fid=58",
        "type": "rss",
        "category": "leak_site",
        "fetch_interval": settings.poll_interval,
        "quality_score": 0.8,
    },
]


def seed_sources() -> None:
    db = SessionLocal()
    try:
        allowed_urls = {s["url"] for s in DEFAULT_SOURCES if s.get("url")}

        # Remove sources that are no longer in DEFAULT_SOURCES
        stale = db.query(Source).filter(Source.url.notin_(allowed_urls)).all()
        for s in stale:
            logger.info(f"Removing stale source: {s.name} ({s.url})")
            db.delete(s)

        # Known-broken sources: mark inactive on seed so they don't spam errors.
        # Re-enable via the API once confirmed working.
        _inactive_urls = {
            "https://umbra.st/syndication.php?fid=58",  # fid=58 returns 504 server-side
        }

        # Seed missing sources; also enforce inactive flag on known-broken sources
        for s in DEFAULT_SOURCES:
            if not s.get("url"):
                continue
            exists = db.query(Source).filter(Source.url == s["url"]).first()
            if not exists:
                active = s["url"] not in _inactive_urls
                db.add(Source(**{**s, "active": active}))
                status = "INACTIVE" if not active else "active"
                logger.info(f"Seeded source ({status}): {s['name']}")
            elif s["url"] in _inactive_urls and exists.active:
                exists.active = False
                logger.info(f"Deactivated known-broken source: {exists.name} ({exists.url})")

        db.commit()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    ensure_runtime_migrations(engine)
    seed_sources()

    scheduler.add_job(
        poll_all_sources,
        "interval",
        seconds=settings.poll_interval,
        jitter=settings.poll_jitter,
        id="poll_all",
        max_instances=1,
    )
    scheduler.start()
    logger.info(f"Scheduler started — polling every {settings.poll_interval}s ±{settings.poll_jitter}s")

    # First poll on startup (non-blocking)
    asyncio.create_task(poll_all_sources())

    yield

    scheduler.shutdown()


app = FastAPI(title="CTI Monitor API", version="1.0.0", lifespan=lifespan)

# Rate limiting (120 req/min per IP)
app.middleware("http")(rate_limit_middleware)

# CORS: configurable via CORS_ALLOWED_ORIGINS env var (comma-separated).
# Use "*" only in local development.
_cors_origins = [o.strip() for o in settings.cors_allowed_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins or ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(threats.router)
app.include_router(sources.router)
app.include_router(actors.router)
app.include_router(dashboard.router)
app.include_router(alerts.router)
app.include_router(admin_auth.router)
_evidence_dir = str(Path(__file__).resolve().parents[1] / "evidence")
app.mount("/evidence", StaticFiles(directory=_evidence_dir), name="evidence")


@app.get("/api/health")
def health():
    return {"status": "ok"}
