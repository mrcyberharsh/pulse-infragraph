"""Explainable, deterministic risk scoring for authorized ASM targets."""
from __future__ import annotations

from typing import Any

RISK_COLORS = {"SAFE": "#22c55e", "EXPOSED": "#f59e0b", "CRITICAL": "#ef4444"}
RISK_KEYWORDS = ("dev", "test", "staging", "admin", "beta", "internal", "api-dev")


def calculate_risk(subdomain: str, technologies: list[str] | None = None,
                   open_ports: list[int] | None = None) -> dict[str, Any]:
    """Return a 0–100 risk score, level, display color, and human-readable reasons.

    Scoring is intentionally transparent. Keyword/technology/port signals are
    heuristics, not proof of vulnerability. Port detection is a placeholder:
    only ports explicitly supplied by an authorized scanner are considered.
    """
    score = 0
    reasons: list[str] = []
    host = subdomain.lower().strip().rstrip(".")
    matched = [word for word in RISK_KEYWORDS if word in host]
    if matched:
        score += 40
        reasons.append(f"Risky hostname keyword(s): {', '.join(matched)} (+40)")
    techs = {item.lower() for item in (technologies or [])}
    if "wordpress" in techs:
        score += 20
        reasons.append("WordPress detected; review version, plugins, and hardening (+20)")
    ports = sorted(set(open_ports or []))
    if ports:
        # Placeholder signal; avoid assuming that every open port is a vulnerability.
        score += min(20, 5 * len(ports))
        reasons.append(f"Open-port signal supplied by scanner: {', '.join(map(str, ports))} (+{min(20, 5 * len(ports))})")
    score = min(100, score)
    level = "SAFE" if score < 30 else "EXPOSED" if score < 60 else "CRITICAL"
    if not reasons:
        reasons.append("No configured risk signals detected; this is not a security guarantee.")
    return {"score": score, "level": level, "color": RISK_COLORS[level], "reasons": reasons}
