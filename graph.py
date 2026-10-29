"""Neo4j persistence and timeline queries. All methods fail clearly when DB is offline."""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from neo4j import GraphDatabase

logger = logging.getLogger(__name__)


class GraphStore:
    """Small Neo4j repository for domains, subdomains, technologies, and risk metadata."""

    def __init__(self, uri: str | None = None, user: str | None = None, password: str | None = None):
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = user or os.getenv("NEO4J_USER", "neo4j")
        self.password = password or os.getenv("NEO4J_PASSWORD", "pulse-infragraph-change-me")
        self.driver = None
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            self.driver.verify_connectivity()
            self.ensure_schema()
        except Exception:
            logger.exception("Neo4j is unavailable at %s", self.uri)
            if self.driver:
                self.driver.close()
            self.driver = None

    @property
    def available(self) -> bool:
        return self.driver is not None

    def ensure_schema(self) -> None:
        if not self.driver:
            return
        with self.driver.session() as session:
            session.run("CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (n:Domain) REQUIRE n.name IS UNIQUE")
            session.run("CREATE CONSTRAINT subdomain_name IF NOT EXISTS FOR (n:Subdomain) REQUIRE n.name IS UNIQUE")
            session.run("CREATE CONSTRAINT tech_name IF NOT EXISTS FOR (n:Tech) REQUIRE n.name IS UNIQUE")

    def upsert_asset(self, domain: str, subdomain: str, risk: dict[str, Any],
                     technologies: list[str] | None = None) -> None:
        """Upsert an asset and preserve first_seen while updating last_seen."""
        if not self.driver:
            raise ConnectionError("Neo4j is offline")
        now = datetime.now(timezone.utc).isoformat()
        with self.driver.session() as session:
            session.run("""
                MERGE (d:Domain {name:$domain})
                MERGE (s:Subdomain {name:$subdomain})
                ON CREATE SET s.first_seen=$now
                SET s.last_seen=$now, s.risk_score=$score, s.risk_level=$level,
                    s.risk_color=$color, s.risk_reasons=$reasons
                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
            """, domain=domain, subdomain=subdomain, now=now,
                 score=risk["score"], level=risk["level"], color=risk["color"], reasons=risk["reasons"])
            for tech in technologies or []:
                session.run("""
                    MATCH (s:Subdomain {name:$subdomain})
                    MERGE (t:Tech {name:$tech})
                    MERGE (s)-[:USES_TECH]->(t)
                """, subdomain=subdomain, tech=tech)

    def get_assets(self) -> list[dict[str, Any]]:
        """Return stored assets with attached technology names."""
        if not self.driver:
            raise ConnectionError("Neo4j is offline")
        with self.driver.session() as session:
            rows = session.run("""
                MATCH (s:Subdomain)
                OPTIONAL MATCH (s)-[:USES_TECH]->(t:Tech)
                RETURN s.name AS name, s.first_seen AS first_seen, s.last_seen AS last_seen,
                       s.risk_score AS score, s.risk_level AS level, s.risk_color AS color,
                       s.risk_reasons AS reasons, collect(t.name) AS technologies
                ORDER BY s.name
            """)
            return [dict(row) for row in rows]

    def get_timeline(self, hours: int = 24) -> list[dict[str, Any]]:
        """Return assets first observed within the last `hours` hours."""
        if not self.driver:
            raise ConnectionError("Neo4j is offline")
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        with self.driver.session() as session:
            rows = session.run("""
                MATCH (s:Subdomain)
                WHERE s.first_seen >= $cutoff
                RETURN s.name AS name, s.first_seen AS first_seen,
                       s.risk_score AS score, s.risk_level AS level
                ORDER BY s.first_seen DESC
            """, cutoff=cutoff)
            return [dict(row) for row in rows]

    def close(self) -> None:
        if self.driver:
            self.driver.close()
            self.driver = None
