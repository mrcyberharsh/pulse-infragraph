"""Explainable, deterministic risk scoring for authorized ASM targets."""
from __future__ import annotations

from typing import Any

RISK_COLORS = {"SAFE": "#22c55e", "EXPOSED": "#f59e0b", "CRITICAL": "#ef4444"}
RISK_KEYWORDS = ("dev", "test", "staging", "admin", "beta", "internal", "api-dev")
DEFAULT_WEIGHTS = {"keyword": 40, "wordpress": 20, "port": 5}


def _normalize_weights(weights: dict[str, int] | None = None) -> dict[str, int]:
    """Merge caller-provided risk weights with sane defaults."""
    merged = DEFAULT_WEIGHTS.copy()
    if weights:
        for key, value in weights.items():
            if key in merged and isinstance(value, int):
                merged[key] = max(0, value)
    return merged


def calculate_risk(subdomain: str, technologies: list[str] | None = None,
                    open_ports: list[int] | None = None,
                    weights: dict[str, int] | None = None) -> dict[str, Any]:
    """Return a 0–100 risk score, level, display color, and human-readable reasons.

    Scoring is intentionally transparent. Keyword/technology/port signals are
    heuristics, not proof of vulnerability. Port detection is a placeholder:
    only ports explicitly supplied by an authorized scanner are considered.
    """
    settings = _normalize_weights(weights)
    score = 0
    reasons: list[str] = []
    host = subdomain.lower().strip().rstrip(".")
    matched = [word for word in RISK_KEYWORDS if word in host]
    if matched:
        score += settings["keyword"]
        reasons.append(f"Risky hostname keyword(s): {', '.join(matched)} (+{settings['keyword']})")
    techs = {item.lower() for item in (technologies or [])}
    if "wordpress" in techs:
        score += settings["wordpress"]
        reasons.append(f"WordPress detected; review version, plugins, and hardening (+{settings['wordpress']})")
    ports = sorted(set(open_ports or []))
    if ports:
        # Placeholder signal; avoid assuming that every open port is a vulnerability.
        port_points = min(20, settings["port"] * len(ports))
        score += port_points
        reasons.append(f"Open-port signal supplied by scanner: {', '.join(map(str, ports))} (+{port_points})")
    score = min(100, score)
    level = "SAFE" if score < 30 else "EXPOSED" if score < 60 else "CRITICAL"
    if not reasons:
        reasons.append("No configured risk signals detected; this is not a security guarantee.")
    return {"score": score, "level": level, "color": RISK_COLORS[level], "reasons": reasons}

