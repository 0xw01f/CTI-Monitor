"""
Actor enrichment service.

normalize_name       – canonical actor identifier
upsert_actor_source  – track per-forum activity
enrich_actor         – compute reputation, spam, specialization, relations
"""

import logging
import re

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..models import Actor, ActorRelation, ActorSource, Threat

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_NON_SAFE = re.compile(r"[^a-z0-9_\-.]")
_MULTI_SEP = re.compile(r"[-_.]{2,}")

# Post types that count as "leaks" for total_leaks
_LEAK_TYPES: frozenset[str] = frozenset({"database", "access"})

# Minimum posts before spam heuristics are applied
_SPAM_MIN_POSTS = 5

# If distinct title-prefix ratio falls below this → spammer
_SPAM_DUP_THRESHOLD = 0.40

# Average risk score below which an actor is flagged (if enough posts)
_SPAM_LOW_SCORE_THRESHOLD = 15


# ---------------------------------------------------------------------------
# Name normalisation
# ---------------------------------------------------------------------------


def normalize_name(name: str) -> str:
    """Return a canonical, safe actor identifier (lowercase, safe chars, ≤100)."""
    if not name:
        return ""
    name = name.lower().strip()
    name = _NON_SAFE.sub("", name)
    name = _MULTI_SEP.sub("-", name)
    return name[:100]


# ---------------------------------------------------------------------------
# Actor source tracking
# ---------------------------------------------------------------------------


def upsert_actor_source(db: Session, actor_id: int, source_name: str) -> None:
    """Increment post_count for this actor × source pair, create row if absent."""
    row = db.query(ActorSource).filter(ActorSource.actor_id == actor_id, ActorSource.source_name == source_name).first()
    if row:
        row.post_count += 1
    else:
        db.add(ActorSource(actor_id=actor_id, source_name=source_name, post_count=1))


# ---------------------------------------------------------------------------
# Spam detection
# ---------------------------------------------------------------------------


def _is_spammer(db: Session, actor: Actor) -> bool:
    """Heuristic spam detection. Conservative — requires multiple signals."""
    post_count = actor.post_count or 0
    if post_count < _SPAM_MIN_POSTS:
        return False

    # Signal 1: very low average risk score
    avg_score = db.query(func.avg(Threat.score)).filter(Threat.actor == actor.username).scalar()
    if avg_score is not None and float(avg_score) < _SPAM_LOW_SCORE_THRESHOLD:
        return True

    # Signal 2: high title repetition (sample last 50)
    rows = (
        db.query(Threat.title).filter(Threat.actor == actor.username).order_by(Threat.fetched_at.desc()).limit(50).all()
    )
    total = len(rows)
    if total >= _SPAM_MIN_POSTS:
        prefixes = {r[0][:30].lower().strip() for r in rows if r[0]}
        if len(prefixes) / total < _SPAM_DUP_THRESHOLD:
            return True

    return False


# ---------------------------------------------------------------------------
# Specialization detection
# ---------------------------------------------------------------------------


def _dominant_type(db: Session, username: str) -> str:
    """Return the most frequent threat type for this actor, or 'other'."""
    row = (
        db.query(Threat.type, func.count(Threat.id).label("n"))
        .filter(Threat.actor == username, Threat.type.isnot(None))
        .group_by(Threat.type)
        .order_by(func.count(Threat.id).desc())
        .first()
    )
    return row[0] if row else "other"


# ---------------------------------------------------------------------------
# Reputation scoring
# ---------------------------------------------------------------------------


def _compute_reputation(actor: Actor, specialization: str) -> tuple[float, str]:
    """
    Return (reputation_score 0–100, risk_level).

    Contributions:
        post activity  → up to 40 pts  (+2 per post)
        leaks          → up to 30 pts  (+5 per leak)
        high-value type→ +10 pts       (database / access)
        spam penalty   → −20 pts

    Risk levels: 0–30 low | 30–60 medium | 60–80 high | 80–100 critical
    """
    post_pts = min(40.0, (actor.post_count or 0) * 2.0)
    leak_pts = min(30.0, (actor.total_leaks or 0) * 5.0)
    type_pts = 10.0 if specialization in ("database", "access") else 0.0
    spam_pen = -20.0 if actor.is_spammer else 0.0

    score = max(0.0, min(100.0, post_pts + leak_pts + type_pts + spam_pen))

    if score >= 80:
        risk = "critical"
    elif score >= 60:
        risk = "high"
    elif score >= 30:
        risk = "medium"
    else:
        risk = "low"

    return round(score, 2), risk


# ---------------------------------------------------------------------------
# Relation detection
# ---------------------------------------------------------------------------


def _upsert_relation(
    db: Session,
    actor_id: int,
    related_id: int,
    relation_type: str,
    confidence: float,
) -> None:
    """Store relation canonical (smaller id first) to prevent duplicates."""
    a, b = (actor_id, related_id) if actor_id < related_id else (related_id, actor_id)
    exists = (
        db.query(ActorRelation)
        .filter(
            ActorRelation.actor_id == a,
            ActorRelation.related_actor_id == b,
            ActorRelation.relation_type == relation_type,
        )
        .first()
    )
    if not exists:
        db.add(
            ActorRelation(
                actor_id=a,
                related_actor_id=b,
                relation_type=relation_type,
                confidence=confidence,
            )
        )


def _detect_relations(db: Session, threat: Threat, actor: Actor) -> None:
    """
    Conservative: link actors sharing the same dedup_key only.
    Requires dedup_key ≥ 8 chars to avoid spurious matches.
    """
    dedup_key = (threat.raw_data or {}).get("dedup_key", "")
    if not dedup_key or len(dedup_key) < 8:
        return

    try:
        peers = (
            db.query(Threat.actor)
            .filter(
                Threat.id != threat.id,
                Threat.actor.isnot(None),
                Threat.actor != actor.username,
                func.json_extract_path_text(Threat.raw_data, "dedup_key") == dedup_key,
            )
            .distinct()
            .limit(5)
            .all()
        )
    except Exception:
        return  # JSON path operator may not be supported for this row type

    for (peer_username,) in peers:
        if not peer_username:
            continue
        peer = db.query(Actor).filter(Actor.username == peer_username).first()
        if peer:
            _upsert_relation(db, actor.id, peer.id, "shared_content", 0.75)
            logger.debug(
                "Actor relation: %s ↔ %s (shared_content, key=%s)",
                actor.username,
                peer_username,
                dedup_key,
            )


# ---------------------------------------------------------------------------
# Main enrichment entry point
# ---------------------------------------------------------------------------


def enrich_actor(db: Session, actor: Actor, threat: Threat) -> None:
    """
    Called from poller after a new threat is flushed (before final commit).

    Updates actor in-place:
        total_leaks       – incremented for database/access posts
        is_spammer        – recomputed heuristically
        specialization    – dominant post type
        reputation_score  – 0–100
        risk_level        – low/medium/high/critical

    Side effects:
        upserts actor_sources row
        detects and stores actor_relations
    """
    # Leak counter
    if threat.type in _LEAK_TYPES:
        actor.total_leaks = (actor.total_leaks or 0) + 1

    # Spam detection (recomputed every call — cheap SQL)
    actor.is_spammer = _is_spammer(db, actor)

    # Dominant type
    actor.specialization = _dominant_type(db, actor.username)

    # Reputation + risk
    actor.reputation_score, actor.risk_level = _compute_reputation(actor, actor.specialization)

    # Source presence
    source_name: str | None = None
    try:
        source_name = threat.source.name if threat.source_id else None
    except Exception:
        pass
    if source_name:
        upsert_actor_source(db, actor.id, source_name)

    # Relation detection
    _detect_relations(db, threat, actor)
