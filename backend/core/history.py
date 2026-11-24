"""Local scan history helpers for pulse-infragraph."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)
DEFAULT_HISTORY_PATH = Path(".pulse-infragraph-history.json")
MAX_HISTORY = 100


def load_history(path: Path = DEFAULT_HISTORY_PATH) -> list[dict[str, Any]]:
    """Read recent scan summaries; malformed files safely return an empty list."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, json.JSONDecodeError):
        logger.warning("Scan history could not be read; returning an empty history.")
        return []
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)][:MAX_HISTORY]


def save_scan(result: dict[str, Any], path: Path = DEFAULT_HISTORY_PATH) -> None:
    """Store a compact scan snapshot, preserving asset-level risk values."""
    assets = []
    for asset in result.get("assets", []):
        risk = asset.get("risk") or {}
        assets.append({
            "subdomain": asset.get("subdomain", ""),
            "score": int(risk.get("score", 0) or 0),
            "level": risk.get("level", "SAFE"),
        })
    snapshot = {
        "scan_id": result.get("scan_id", ""),
        "domain": result.get("domain", ""),
        "timestamp": result.get("timestamp", ""),
        "asset_count": len(assets),
        "critical_count": sum(1 for item in assets if item["level"] == "CRITICAL"),
        "exposed_count": sum(1 for item in assets if item["level"] == "EXPOSED"),
        "assets": assets,
    }
    history = load_history(path)
    history.insert(0, snapshot)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(history[:MAX_HISTORY], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    temporary.replace(path)


def compare_scans(history: list[dict[str, Any]]) -> dict[str, int] | None:
    """Compare the two latest snapshots for the same domain."""
    if len(history) < 2:
        return None
    latest = history[0]
    previous = next(
        (item for item in history[1:] if item.get("domain") == latest.get("domain")),
        None,
    )
    if previous is None:
        return None
    current_hosts = {item.get("subdomain") for item in latest.get("assets", [])}
    previous_hosts = {item.get("subdomain") for item in previous.get("assets", [])}
    return {
        "new_assets": len(current_hosts - previous_hosts),
        "removed_assets": len(previous_hosts - current_hosts),
        "risk_score_delta": sum(
            int(item.get("score", 0) or 0) for item in latest.get("assets", [])
        ) - sum(int(item.get("score", 0) or 0) for item in previous.get("assets", [])),
    }
