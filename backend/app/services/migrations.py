from sqlalchemy import text


def ensure_runtime_migrations(engine) -> None:
    statements = [
        # ── actors new columns ────────────────────────────────────────────────
        "ALTER TABLE actors ADD COLUMN IF NOT EXISTS total_leaks INTEGER DEFAULT 0",
        "ALTER TABLE actors ADD COLUMN IF NOT EXISTS reputation_score DOUBLE PRECISION DEFAULT 0.0",
        "ALTER TABLE actors ADD COLUMN IF NOT EXISTS risk_level VARCHAR DEFAULT 'low'",
        "ALTER TABLE actors ADD COLUMN IF NOT EXISTS is_spammer BOOLEAN DEFAULT FALSE",
        "ALTER TABLE actors ADD COLUMN IF NOT EXISTS specialization VARCHAR DEFAULT 'other'",
        # ── actor_sources ─────────────────────────────────────────────────────
        """
        CREATE TABLE IF NOT EXISTS actor_sources (
            id SERIAL PRIMARY KEY,
            actor_id INTEGER NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
            source_name VARCHAR NOT NULL,
            post_count INTEGER DEFAULT 1,
            CONSTRAINT uq_actor_source UNIQUE (actor_id, source_name)
        )
        """,
        # ── actor_relations ───────────────────────────────────────────────────
        """
        CREATE TABLE IF NOT EXISTS actor_relations (
            id SERIAL PRIMARY KEY,
            actor_id INTEGER NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
            related_actor_id INTEGER NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
            relation_type VARCHAR NOT NULL,
            confidence DOUBLE PRECISION DEFAULT 0.5,
            CONSTRAINT uq_actor_relation UNIQUE (actor_id, related_actor_id, relation_type)
        )
        """,
        # ── sources stability flag ────────────────────────────────────────────
        "ALTER TABLE sources ADD COLUMN IF NOT EXISTS is_unstable BOOLEAN DEFAULT FALSE",
        # ── soft-delete support ───────────────────────────────────────────────
        "ALTER TABLE threats ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN NOT NULL DEFAULT FALSE",
        # ── public moderation visibility ──────────────────────────────────────
        "ALTER TABLE threats ADD COLUMN IF NOT EXISTS is_public BOOLEAN NOT NULL DEFAULT TRUE",
        # ── pre-existing columns (safe to re-run) ─────────────────────────────
        "ALTER TABLE threats ADD COLUMN IF NOT EXISTS actor_profile_url VARCHAR",
        "ALTER TABLE threats ADD COLUMN IF NOT EXISTS actor_profile_id VARCHAR",
        "ALTER TABLE threats ADD COLUMN IF NOT EXISTS full_post_html TEXT",
        "ALTER TABLE threats ADD COLUMN IF NOT EXISTS full_post_text TEXT",
        "ALTER TABLE actors ADD COLUMN IF NOT EXISTS profile_url VARCHAR",
        "ALTER TABLE actors ADD COLUMN IF NOT EXISTS profile_id VARCHAR",
        "ALTER TABLE actors ADD COLUMN IF NOT EXISTS source_host VARCHAR",
        "ALTER TABLE actors ADD COLUMN IF NOT EXISTS username_history JSON",
        """
        CREATE TABLE IF NOT EXISTS threat_links (
            id SERIAL PRIMARY KEY,
            threat_id INTEGER NOT NULL REFERENCES threats(id) ON DELETE CASCADE,
            url TEXT NOT NULL,
            domain VARCHAR,
            link_type VARCHAR DEFAULT 'external',
            CONSTRAINT uq_threat_link UNIQUE (threat_id, url)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS actor_contacts (
            id SERIAL PRIMARY KEY,
            actor_id INTEGER NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
            kind VARCHAR NOT NULL,
            value VARCHAR NOT NULL,
            confidence DOUBLE PRECISION DEFAULT 0.8,
            CONSTRAINT uq_actor_contact UNIQUE (actor_id, kind, value)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS graph_entities (
            id SERIAL PRIMARY KEY,
            entity_type VARCHAR NOT NULL,
            value TEXT NOT NULL,
            normalized_value TEXT NOT NULL,
            first_seen TIMESTAMP DEFAULT NOW(),
            last_seen TIMESTAMP DEFAULT NOW(),
            seen_count INTEGER DEFAULT 1,
            CONSTRAINT uq_entity_type_normalized UNIQUE (entity_type, normalized_value)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS threat_entities (
            id SERIAL PRIMARY KEY,
            threat_id INTEGER NOT NULL REFERENCES threats(id) ON DELETE CASCADE,
            entity_id INTEGER NOT NULL REFERENCES graph_entities(id) ON DELETE CASCADE,
            role VARCHAR,
            confidence DOUBLE PRECISION DEFAULT 0.8,
            CONSTRAINT uq_threat_entity_role UNIQUE (threat_id, entity_id, role)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS graph_relations (
            id SERIAL PRIMARY KEY,
            source_entity_id INTEGER NOT NULL REFERENCES graph_entities(id) ON DELETE CASCADE,
            target_entity_id INTEGER NOT NULL REFERENCES graph_entities(id) ON DELETE CASCADE,
            relation_type VARCHAR NOT NULL,
            weight DOUBLE PRECISION DEFAULT 1.0,
            last_seen TIMESTAMP DEFAULT NOW(),
            CONSTRAINT uq_graph_relation UNIQUE (source_entity_id, target_entity_id, relation_type)
        )
        """,
    ]
    with engine.begin() as conn:
        for stmt in statements:
            conn.execute(text(stmt))
