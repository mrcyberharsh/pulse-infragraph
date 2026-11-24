"""Explainable heuristic risk scoring for authorized asset inventories."""
from __future__ import annotations

from typing import Any

RISK_COLORS = {"SAFE": "#22c55e", "EXPOSED": "#f59e0b", "CRITICAL": "#ef4444"}
RISK_KEYWORDS = ("dev", "test", "staging", "admin", "beta", "internal", "api-dev")
DEFAULT_WEIGHTS = {"keyword": 40, "wordpress": 20, "port": 5}


def _normalize_weights(weights: dict[str, int] | None = None) -> dict[str, int]:
    merged = DEFAULT_WEIGHTS.copy()
    if weights:
        for key, value in weights.items():
            if key in merged and isinstance(value, int) and not isinstance(value, bool):
                merged[key] = max(0, min(value, 100))
    return merged


def calculate_risk(
    subdomain: str,
    technologies: list[str] | None = None,
    open_ports: list[int] | None = None,
    weights: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Return a bounded score and reasons; signals are not vulnerability proof."""
    settings = _normalize_weights(weights)
    host = (subdomain or "").lower().strip().rstrip(".")
    score = 0
    reasons: list[str] = []

    matched = [word for word in RISK_KEYWORDS if word in host]
    if matched:
        score += settings["keyword"]
        reasons.append(
            f"Hostname keyword(s): {', '.join(matched)} (+{settings['keyword']})"
        )

    techs = {str(item).lower() for item in (technologies or [])}
    if "wordpress" in techs:
        score += settings["wordpress"]
        reasons.append(
            f"WordPress detected; review patching and hardening (+{settings['wordpress']})"
        )

    ports = sorted({int(port) for port in (open_ports or []) if 1 <= int(port) <= 65535})
    if ports:
        points = min(20, settings["port"] * len(ports))
        score += points
        reasons.append(f"Open-port signal supplied by an authorized scanner (+{points})")

    score = max(0, min(100, score))
    level = "SAFE" if score < 30 else "EXPOSED" if score < 60 else "CRITICAL"
    if not reasons:
        reasons.append("No configured heuristic signals detected; this is not a security guarantee.")
    return {
        "score": score,
        "level": level,
        "color": RISK_COLORS[level],
        "reasons": reasons,
    }
