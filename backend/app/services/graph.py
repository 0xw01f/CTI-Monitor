from collections.abc import Iterable
from datetime import datetime

from sqlalchemy.orm import Session

from ..models import GraphEntity, GraphRelation, Threat, ThreatEntity


def _normalize(value: str) -> str:
    return (value or "").strip().lower()


def upsert_graph_entity(db: Session, entity_type: str, value: str) -> GraphEntity | None:
    value = (value or "").strip()
    if not value:
        return None

    normalized = _normalize(value)
    entity = (
        db.query(GraphEntity)
        .filter(
            GraphEntity.entity_type == entity_type,
            GraphEntity.normalized_value == normalized,
        )
        .first()
    )

    now = datetime.utcnow()
    if entity:
        entity.last_seen = now
        entity.seen_count = (entity.seen_count or 0) + 1
        return entity

    entity = GraphEntity(
        entity_type=entity_type,
        value=value,
        normalized_value=normalized,
        first_seen=now,
        last_seen=now,
        seen_count=1,
    )
    db.add(entity)
    db.flush()
    return entity


def link_entity_to_threat(db: Session, threat_id: int, entity_id: int, role: str, confidence: float = 0.8) -> None:
    exists = (
        db.query(ThreatEntity)
        .filter(
            ThreatEntity.threat_id == threat_id,
            ThreatEntity.entity_id == entity_id,
            ThreatEntity.role == role,
        )
        .first()
    )
    if exists:
        return
    db.add(
        ThreatEntity(
            threat_id=threat_id,
            entity_id=entity_id,
            role=role,
            confidence=confidence,
        )
    )


def upsert_relation(
    db: Session,
    source_entity_id: int,
    target_entity_id: int,
    relation_type: str,
    weight: float = 1.0,
) -> None:
    if source_entity_id == target_entity_id:
        return

    src, dst = sorted([source_entity_id, target_entity_id])
    rel = (
        db.query(GraphRelation)
        .filter(
            GraphRelation.source_entity_id == src,
            GraphRelation.target_entity_id == dst,
            GraphRelation.relation_type == relation_type,
        )
        .first()
    )

    now = datetime.utcnow()
    if rel:
        rel.weight = (rel.weight or 0.0) + weight
        rel.last_seen = now
        return

    db.add(
        GraphRelation(
            source_entity_id=src,
            target_entity_id=dst,
            relation_type=relation_type,
            weight=weight,
            last_seen=now,
        )
    )


def build_threat_graph(
    db: Session,
    threat: Threat,
    domains: Iterable[str],
    urls: Iterable[str],
    actor_contacts: Iterable[dict],
) -> None:
    entity_ids: list[int] = []

    seeds = [
        ("actor", threat.actor, "actor", 0.95),
        ("actor_profile_id", threat.actor_profile_id, "identity", 0.98),
        ("country", threat.country, "victim_geo", 0.7),
        ("threat_type", threat.type, "classification", 0.85),
        ("severity", threat.severity, "classification", 0.9),
    ]
    for t in threat.tags or []:
        seeds.append(("tag", t, "tag", 0.8))
    for d in domains:
        seeds.append(("domain", d, "ioc", 0.85))
    for u in urls:
        seeds.append(("url", u, "ioc", 0.8))
    for c in actor_contacts:
        seeds.append(
            (
                f"contact_{c.get('kind', 'unknown')}",
                c.get("value"),
                "contact",
                float(c.get("confidence", 0.75)),
            )
        )

    seen_links: set[tuple] = set()
    for entity_type, value, role, confidence in seeds:
        entity = upsert_graph_entity(db, entity_type, str(value or ""))
        if not entity:
            continue
        key = (entity.id, role)
        if key not in seen_links:
            link_entity_to_threat(db, threat.id, entity.id, role, confidence)
            seen_links.add(key)
        entity_ids.append(entity.id)

    uniq_ids = sorted(set(entity_ids))
    for i in range(len(uniq_ids)):
        for j in range(i + 1, len(uniq_ids)):
            upsert_relation(db, uniq_ids[i], uniq_ids[j], relation_type="cooccurs_in_threat", weight=1.0)
