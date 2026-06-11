from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Actor, ActorContact, ActorRelation, ActorSource, Threat
from ..services.actor_service import normalize_name
from ..services.identity import strip_tags

router = APIRouter(prefix="/api/actors", tags=["actors"])


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _actor_summary(a: Actor) -> dict:
    return {
        "id": a.id,
        "username": strip_tags(a.username),
        "platform": a.platform,
        "specialization": a.specialization or "other",
        "first_seen": a.first_seen.isoformat() if a.first_seen else None,
        "last_seen": a.last_seen.isoformat() if a.last_seen else None,
        "post_count": a.post_count or 0,
        "total_leaks": a.total_leaks or 0,
        "reputation_score": round(a.reputation_score or 0.0, 1),
        "risk_level": a.risk_level or "low",
        "is_spammer": bool(a.is_spammer),
    }


def _actor_detail(a: Actor, db: Session) -> dict:
    d = _actor_summary(a)
    d["activity_score"] = a.activity_score
    d["username_history"] = a.username_history or []
    d["tags"] = a.tags or []

    # Sources / forums where active
    sources = db.query(ActorSource).filter(ActorSource.actor_id == a.id).order_by(ActorSource.post_count.desc()).all()
    d["sources"] = [{"name": s.source_name, "post_count": s.post_count} for s in sources]
    d["source_names"] = [s.source_name for s in sources]

    # Identities / contacts (presented as spec's "identities" field)
    contacts = (
        db.query(ActorContact)
        .filter(ActorContact.actor_id == a.id)
        .order_by(ActorContact.kind.asc(), ActorContact.value.asc())
        .all()
    )
    d["identities"] = [{"type": c.kind, "value": c.value, "confidence": c.confidence} for c in contacts]

    # Recent threats
    d["recent_threats"] = [
        {
            "id": t.id,
            "title": t.title,
            "type": t.type,
            "severity": t.severity,
            "score": t.score,
            "country": t.country,
            "fetched_at": t.fetched_at.isoformat() if t.fetched_at else None,
            "published_at": t.published_at.isoformat() if t.published_at else None,
        }
        for t in (
            db.query(Threat).filter(Threat.actor == a.username).order_by(Threat.fetched_at.desc()).limit(20).all()
        )
    ]

    return d


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/")
def list_actors(
    risk_level: str | None = Query(None, description="Filter: low / medium / high / critical"),
    is_spammer: bool | None = Query(None, description="true → only spammers, false → exclude them"),
    search: str | None = Query(None, description="Username prefix search"),
    specialization: str | None = Query(None, description="Filter by specialization"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    q = db.query(Actor)

    if risk_level:
        q = q.filter(Actor.risk_level == risk_level)
    if is_spammer is not None:
        q = q.filter(Actor.is_spammer == is_spammer)
    if specialization:
        q = q.filter(Actor.specialization == specialization)
    if search:
        q = q.filter(Actor.username.ilike(f"{search}%"))

    total = q.count()
    actors = q.order_by(Actor.reputation_score.desc(), Actor.post_count.desc()).offset(offset).limit(limit).all()
    return {"total": total, "actors": [_actor_summary(a) for a in actors]}


@router.get("/{username}")
def get_actor(username: str, db: Session = Depends(get_db)):
    # Try exact match first, then normalized form
    actor = db.query(Actor).filter(Actor.username == username).first()
    if not actor:
        norm = normalize_name(username)
        actor = db.query(Actor).filter(Actor.username == norm).first()
    if not actor:
        # Defensive: legacy usernames may still contain HTML anchors.
        # Fallback to a substring search on the raw stored username.
        actor = db.query(Actor).filter(Actor.username.ilike(f"%{username}%")).first()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")

    return _actor_detail(actor, db)


@router.get("/{username}/relations")
def get_actor_relations(username: str, db: Session = Depends(get_db)):
    actor = db.query(Actor).filter(Actor.username == username).first()
    if not actor:
        norm = normalize_name(username)
        actor = db.query(Actor).filter(Actor.username == norm).first()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")

    relations = (
        db.query(ActorRelation)
        .filter((ActorRelation.actor_id == actor.id) | (ActorRelation.related_actor_id == actor.id))
        .all()
    )

    result = []
    for r in relations:
        other_id = r.related_actor_id if r.actor_id == actor.id else r.actor_id
        other = db.query(Actor).filter(Actor.id == other_id).first()
        if other:
            result.append(
                {
                    "username": strip_tags(other.username),
                    "relation_type": r.relation_type,
                    "confidence": r.confidence,
                    "risk_level": other.risk_level or "low",
                    "reputation_score": round(other.reputation_score or 0.0, 1),
                    "specialization": other.specialization or "other",
                }
            )

    return {"actor": username, "relations": result}
