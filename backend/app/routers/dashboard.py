from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import case, func, or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Actor, Source, Threat
from ..services.admin_auth import get_optional_admin

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats")
def get_stats(
    db: Session = Depends(get_db),
    claims: dict | None = Depends(get_optional_admin),
):
    now = datetime.utcnow()
    is_admin = bool(claims and claims.get("role") == "admin")

    effective_date = func.coalesce(Threat.published_at, Threat.fetched_at)
    active_filter = Threat.is_deleted.is_(False)
    public_filter = Threat.is_public.is_(True)
    scope_filter = active_filter if is_admin else (active_filter & public_filter)
    threats_24h = db.query(Threat).filter(scope_filter, effective_date >= now - timedelta(hours=24)).count()
    threats_7d = db.query(Threat).filter(scope_filter, effective_date >= now - timedelta(days=7)).count()
    total_threats = db.query(Threat).filter(scope_filter).count()
    high_priority_24h = (
        db.query(Threat)
        .filter(
            scope_filter,
            effective_date >= now - timedelta(hours=24),
            or_(Threat.severity.in_(["critical", "high"]), Threat.score >= 75),
        )
        .count()
    )
    deleted_24h = (
        db.query(Threat)
        .filter(
            Threat.is_deleted.is_(True),
            effective_date >= now - timedelta(hours=24),
        )
        .count()
    )

    severity_breakdown = dict(
        db.query(Threat.severity, func.count(Threat.id)).filter(scope_filter).group_by(Threat.severity).all()
    )
    type_breakdown = dict(db.query(Threat.type, func.count(Threat.id)).filter(scope_filter).group_by(Threat.type).all())

    actor_risk_breakdown = dict(db.query(Actor.risk_level, func.count(Actor.id)).group_by(Actor.risk_level).all())
    critical_actors = db.query(Actor).filter(Actor.risk_level == "critical").count()
    high_risk_actors = db.query(Actor).filter(Actor.risk_level.in_(["critical", "high"])).count()

    top_actors = db.query(Actor).order_by(Actor.post_count.desc()).limit(8).all()

    source_health_rows = db.query(
        func.count(Source.id).label("total_sources"),
        func.sum(case((Source.active.is_(True), 1), else_=0)).label("active_sources"),
        func.sum(case((Source.is_unstable.is_(True), 1), else_=0)).label("unstable_sources"),
        func.sum(case((Source.error_count >= 3, 1), else_=0)).label("degraded_sources"),
    ).one()

    target_hotspots_rows = (
        db.query(
            func.lower(Threat.target).label("target"),
            func.count(Threat.id).label("count"),
        )
        .filter(
            scope_filter,
            Threat.target.isnot(None),
            func.length(func.trim(Threat.target)) > 0,
            effective_date >= now - timedelta(days=30),
        )
        .group_by(func.lower(Threat.target))
        .order_by(func.count(Threat.id).desc())
        .limit(8)
        .all()
    )

    country_hotspots_rows = (
        db.query(
            Threat.country.label("country"),
            func.count(Threat.id).label("count"),
        )
        .filter(
            scope_filter,
            Threat.country.isnot(None),
            func.length(func.trim(Threat.country)) > 0,
            effective_date >= now - timedelta(days=30),
        )
        .group_by(Threat.country)
        .order_by(func.count(Threat.id).desc())
        .limit(8)
        .all()
    )

    recent_threats = (
        db.query(Threat)
        .filter(scope_filter)
        .order_by(func.coalesce(Threat.published_at, Threat.fetched_at).desc())
        .limit(10)
        .all()
    )

    analyst_queue = (
        db.query(Threat)
        .filter(
            scope_filter,
            effective_date >= now - timedelta(hours=48),
            or_(Threat.severity.in_(["critical", "high"]), Threat.score >= 75),
        )
        .order_by(Threat.score.desc(), effective_date.desc())
        .limit(6)
        .all()
    )

    return {
        "threats_24h": threats_24h,
        "threats_7d": threats_7d,
        "high_priority_24h": high_priority_24h,
        "deleted_24h": deleted_24h,
        "total_threats": total_threats,
        "hidden_threats": (
            db.query(Threat).filter(active_filter, Threat.is_public.is_(False)).count() if is_admin else 0
        ),
        "total_sources": int(source_health_rows.total_sources or 0),
        "active_sources": int(source_health_rows.active_sources or 0),
        "source_health": {
            "unstable_sources": int(source_health_rows.unstable_sources or 0),
            "degraded_sources": int(source_health_rows.degraded_sources or 0),
        },
        "severity_breakdown": severity_breakdown,
        "type_breakdown": type_breakdown,
        "actor_risk_breakdown": actor_risk_breakdown,
        "critical_actors": critical_actors,
        "high_risk_actors": high_risk_actors,
        "target_hotspots": [{"target": r.target, "count": r.count} for r in target_hotspots_rows],
        "country_hotspots": [{"country": r.country, "count": r.count} for r in country_hotspots_rows],
        "top_actors": [
            {
                "username": a.username,
                "post_count": a.post_count,
                "platform": a.platform,
                "risk_level": a.risk_level,
                "specialization": a.specialization,
            }
            for a in top_actors
        ],
        "recent_threats": [
            {
                "id": t.id,
                "title": t.title,
                "type": t.type,
                "severity": t.severity,
                "score": t.score,
                "actor": t.actor,
                "published_at": (
                    (t.published_at or t.fetched_at).isoformat() if (t.published_at or t.fetched_at) else None
                ),
            }
            for t in recent_threats
        ],
        "analyst_queue": [
            {
                "id": t.id,
                "title": t.title,
                "type": t.type,
                "severity": t.severity,
                "score": t.score,
                "actor": t.actor,
                "target": t.target,
                "country": t.country,
                "published_at": (
                    (t.published_at or t.fetched_at).isoformat() if (t.published_at or t.fetched_at) else None
                ),
            }
            for t in analyst_queue
        ],
    }


@router.get("/timeline")
def get_timeline(
    days: int = 7,
    db: Session = Depends(get_db),
    claims: dict | None = Depends(get_optional_admin),
):
    cutoff = datetime.utcnow() - timedelta(days=days)
    is_admin = bool(claims and claims.get("role") == "admin")
    effective_date = func.coalesce(Threat.published_at, Threat.fetched_at)
    active_filter = Threat.is_deleted.is_(False)
    scope_filter = active_filter if is_admin else (active_filter & Threat.is_public.is_(True))
    rows = (
        db.query(
            func.date(effective_date).label("date"),
            func.count(Threat.id).label("count"),
        )
        .filter(scope_filter, effective_date >= cutoff)
        .group_by(func.date(effective_date))
        .order_by(func.date(effective_date))
        .all()
    )
    return [{"date": str(r.date), "count": r.count} for r in rows]
