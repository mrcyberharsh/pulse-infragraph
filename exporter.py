"""Portable exports for common bug-bounty workflows."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Iterable


def export_nuclei_txt(subdomains: Iterable[str]) -> str:
    """Return one normalized host per line for use as a Nuclei target list."""
    hosts = sorted({str(host).strip() for host in subdomains if str(host).strip()})
    return "\n".join(hosts) + ("\n" if hosts else "")


def export_bugbounty_json(data: dict[str, Any]) -> str:
    """Serialize a report with mandatory tool credit and scan metadata."""
    report = {
        "tool": "pulse-infragraph",
        "version": "1.5.0 Community Edition",
        "credit": "Created by Harsh Saini (MR CYBER PULSE)",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "domain": data.get("domain", ""),
        "findings": [
            {
                "subdomain": asset.get("subdomain", asset.get("name", "")),
                "risk": asset.get("risk", {
                    "score": asset.get("score", 0),
                    "level": asset.get("level", "SAFE"),
                    "color": asset.get("color", "#22c55e"),
                    "reasons": asset.get("reasons", []),
                }),
                "technologies": asset.get("fingerprint", {}).get("technologies", asset.get("technologies", [])),
            }
            for asset in data.get("assets", data.get("findings", []))
        ],
    }
    return json.dumps(report, indent=2, ensure_ascii=False)


def export_csv(data: dict[str, Any]) -> str:
    """Create a CSV containing asset, risk, reason, and technology columns."""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["domain", "subdomain", "risk_score", "risk_level", "risk_reasons", "technologies"])
    writer.writeheader()
    for asset in data.get("assets", data.get("findings", [])):
        risk = asset.get("risk", {})
        writer.writerow({
            "domain": data.get("domain", asset.get("domain", "")),
            "subdomain": asset.get("subdomain", asset.get("name", "")),
            "risk_score": risk.get("score", asset.get("score", 0)),
            "risk_level": risk.get("level", asset.get("level", "SAFE")),
            "risk_reasons": "; ".join(risk.get("reasons", asset.get("reasons", []))),
            "technologies": ", ".join(asset.get("fingerprint", {}).get("technologies", asset.get("technologies", []))),
        })
    return output.getvalue()
