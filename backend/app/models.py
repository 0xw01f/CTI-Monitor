from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from .database import Base


class Source(Base):
    __tablename__ = "sources"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False)
    type = Column(String, nullable=False)  # 'rss', 'telegram', 'scraper'
    category = Column(String)  # 'forum', 'leak_site', 'telegram'
    active = Column(Boolean, default=True)
    last_fetch = Column(DateTime, nullable=True)
    fetch_interval = Column(Integer, default=300)
    quality_score = Column(Float, default=0.5)
    error_count = Column(Integer, default=0)
    last_error = Column(Text, nullable=True)
    is_unstable = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())

    threats = relationship("Threat", back_populates="source")


class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    source_id = Column(Integer, ForeignKey("sources.id"))
    external_id = Column(String)
    title = Column(String, nullable=False)
    content = Column(Text)
    full_post_html = Column(Text, nullable=True)
    full_post_text = Column(Text, nullable=True)
    url = Column(String)
    type = Column(String, default="other")  # ransomware, leak, malware, access, other
    severity = Column(String, default="medium")  # low, medium, high, critical
    score = Column(Integer, default=50)
    actor = Column(String, nullable=True)
    actor_profile_url = Column(String, nullable=True)
    actor_profile_id = Column(String, nullable=True)
    target = Column(String, nullable=True)
    country = Column(String, nullable=True)
    victim_origin_method = Column(String, nullable=True)
    victim_origin_confidence = Column(Float, default=0.0)
    victim_origin_evidence = Column(String, nullable=True)
    post_screenshot_path = Column(String, nullable=True)
    tags = Column(JSON, default=list)
    published_at = Column(DateTime, nullable=True)
    fetched_at = Column(DateTime, server_default=func.now())
    raw_data = Column(JSON)
    is_deleted = Column(Boolean, default=False, nullable=False)
    is_public = Column(Boolean, default=True, nullable=False)

    source = relationship("Source", back_populates="threats")
    links = relationship("ThreatLink", back_populates="threat", cascade="all, delete-orphan")
    graph_entities = relationship("ThreatEntity", back_populates="threat", cascade="all, delete-orphan")
    social_posts = relationship("SocialPost", back_populates="threat", cascade="all, delete-orphan")

    __table_args__ = (UniqueConstraint("source_id", "external_id", name="uq_source_external"),)


class ThreatLink(Base):
    __tablename__ = "threat_links"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id"), nullable=False, index=True)
    url = Column(Text, nullable=False)
    domain = Column(String, nullable=True)
    link_type = Column(String, default="external")

    threat = relationship("Threat", back_populates="links")

    __table_args__ = (UniqueConstraint("threat_id", "url", name="uq_threat_link"),)


class Actor(Base):
    __tablename__ = "actors"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False, unique=True)
    profile_url = Column(String, nullable=True)
    profile_id = Column(String, nullable=True)
    source_host = Column(String, nullable=True)
    username_history = Column(JSON, default=list)
    platform = Column(String)
    first_seen = Column(DateTime, server_default=func.now())
    last_seen = Column(DateTime, server_default=func.now())
    post_count = Column(Integer, default=1)
    total_leaks = Column(Integer, default=0)
    activity_score = Column(Float, default=0.0)
    reputation_score = Column(Float, default=0.0)
    risk_level = Column(String, default="low")  # low / medium / high / critical
    is_spammer = Column(Boolean, default=False)
    # database / access / credentials / stealer_logs / other
    specialization = Column(String, default="other")
    tags = Column(JSON, default=list)
    created_at = Column(DateTime, server_default=func.now())

    contacts = relationship("ActorContact", back_populates="actor", cascade="all, delete-orphan")
    sources = relationship("ActorSource", back_populates="actor", cascade="all, delete-orphan")
    relations_from = relationship(
        "ActorRelation",
        foreign_keys="ActorRelation.actor_id",
        back_populates="actor",
        cascade="all, delete-orphan",
    )


class ActorContact(Base):
    __tablename__ = "actor_contacts"

    id = Column(Integer, primary_key=True, index=True)
    actor_id = Column(Integer, ForeignKey("actors.id"), nullable=False, index=True)
    kind = Column(String, nullable=False, index=True)
    value = Column(String, nullable=False)
    confidence = Column(Float, default=0.8)

    actor = relationship("Actor", back_populates="contacts")

    __table_args__ = (UniqueConstraint("actor_id", "kind", "value", name="uq_actor_contact"),)


class GraphEntity(Base):
    __tablename__ = "graph_entities"

    id = Column(Integer, primary_key=True, index=True)
    entity_type = Column(String, nullable=False, index=True)
    value = Column(Text, nullable=False)
    normalized_value = Column(Text, nullable=False, index=True)
    first_seen = Column(DateTime, server_default=func.now())
    last_seen = Column(DateTime, server_default=func.now())
    seen_count = Column(Integer, default=1)

    threats = relationship("ThreatEntity", back_populates="entity", cascade="all, delete-orphan")

    __table_args__ = (UniqueConstraint("entity_type", "normalized_value", name="uq_entity_type_normalized"),)


class ThreatEntity(Base):
    __tablename__ = "threat_entities"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id"), nullable=False, index=True)
    entity_id = Column(Integer, ForeignKey("graph_entities.id"), nullable=False, index=True)
    role = Column(String, nullable=True)
    confidence = Column(Float, default=0.8)

    threat = relationship("Threat", back_populates="graph_entities")
    entity = relationship("GraphEntity", back_populates="threats")

    __table_args__ = (UniqueConstraint("threat_id", "entity_id", "role", name="uq_threat_entity_role"),)


class GraphRelation(Base):
    __tablename__ = "graph_relations"

    id = Column(Integer, primary_key=True, index=True)
    source_entity_id = Column(Integer, ForeignKey("graph_entities.id"), nullable=False, index=True)
    target_entity_id = Column(Integer, ForeignKey("graph_entities.id"), nullable=False, index=True)
    relation_type = Column(String, nullable=False, index=True)
    weight = Column(Float, default=1.0)
    last_seen = Column(DateTime, server_default=func.now())

    __table_args__ = (
        UniqueConstraint(
            "source_entity_id",
            "target_entity_id",
            "relation_type",
            name="uq_graph_relation",
        ),
    )


class SocialPost(Base):
    """Tracks social media posts published for a given threat."""

    __tablename__ = "social_posts"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id"), nullable=False, index=True)
    platform = Column(String, nullable=False)  # bluesky, x
    post_url = Column(String, nullable=True)
    status = Column(String, default="published")  # published, failed
    detail = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    threat = relationship("Threat", back_populates="social_posts")


class ActorSource(Base):
    """Tracks how many posts each actor has per source/forum."""

    __tablename__ = "actor_sources"

    id = Column(Integer, primary_key=True, index=True)
    actor_id = Column(Integer, ForeignKey("actors.id"), nullable=False, index=True)
    source_name = Column(String, nullable=False)
    post_count = Column(Integer, default=1)

    actor = relationship("Actor", back_populates="sources")

    __table_args__ = (UniqueConstraint("actor_id", "source_name", name="uq_actor_source"),)


class ActorRelation(Base):
    """Directed relation between two actors (stored canonical: actor_id < related_actor_id)."""

    __tablename__ = "actor_relations"

    id = Column(Integer, primary_key=True, index=True)
    actor_id = Column(Integer, ForeignKey("actors.id"), nullable=False, index=True)
    related_actor_id = Column(Integer, ForeignKey("actors.id"), nullable=False, index=True)
    # repost / same_content / shared_contact / shared_content
    relation_type = Column(String, nullable=False)
    confidence = Column(Float, default=0.5)

    actor = relationship("Actor", foreign_keys=[actor_id], back_populates="relations_from")
    related_actor = relationship("Actor", foreign_keys=[related_actor_id])

    __table_args__ = (UniqueConstraint("actor_id", "related_actor_id", "relation_type", name="uq_actor_relation"),)
