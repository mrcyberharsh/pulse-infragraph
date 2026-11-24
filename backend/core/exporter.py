"""Report exporters for pulse-infragraph scan results."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any


def export_bugbounty_json(data: dict[str, Any]) -> str:
    """Serialize a scan result as a portable JSON report."""
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def export_csv(data: dict[str, Any]) -> str:
    """Export one row per discovered asset."""
    output = io.StringIO(newline="")
    fields = [
        "domain", "subdomain", "risk_score", "risk_level",
        "technologies", "http_status", "url",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for asset in data.get("assets", []):
        risk = asset.get("risk") or {}
        fingerprint = asset.get("fingerprint") or {}
        writer.writerow({
            "domain": asset.get("domain") or data.get("domain", ""),
            "subdomain": asset.get("subdomain", ""),
            "risk_score": risk.get("score", ""),
            "risk_level": risk.get("level", ""),
            "technologies": ", ".join(fingerprint.get("technologies") or []),
            "http_status": fingerprint.get("status", ""),
            "url": fingerprint.get("final_url") or fingerprint.get("url", ""),
        })
    return output.getvalue()


def export_nuclei_txt(hosts: list[str]) -> str:
    """Export normalized hostnames as a plain text scope list."""
    return "\n".join(sorted({host.strip() for host in hosts if host and host.strip()})) + "\n"


def export_pdf(data: dict[str, Any]) -> bytes:
    """Build a compact PDF inventory report in memory using ReportLab."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    )

    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer, pagesize=landscape(A4),
        rightMargin=14 * mm, leftMargin=14 * mm,
        topMargin=14 * mm, bottomMargin=14 * mm,
        title="pulse-infragraph Asset Report",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], alignment=TA_CENTER))
    story = [
        Paragraph("pulse-infragraph — Asset Inventory Report", styles["ReportTitle"]),
        Spacer(1, 5 * mm),
        Paragraph(f"Domain: {data.get('domain', 'N/A')}", styles["Normal"]),
        Paragraph(f"Generated: {datetime.now(timezone.utc).isoformat()}", styles["Normal"]),
        Paragraph(
            "Heuristic findings are indicators only, not confirmation of vulnerabilities.",
            styles["Italic"],
        ),
        Spacer(1, 5 * mm),
    ]
    rows = [["Host", "Risk", "Level", "HTTP", "Technologies"]]
    for asset in data.get("assets", []):
        risk = asset.get("risk") or {}
        fp = asset.get("fingerprint") or {}
        rows.append([
            str(asset.get("subdomain", ""))[:80],
            str(risk.get("score", "")),
            str(risk.get("level", "")),
            str(fp.get("status") or ""),
            ", ".join(fp.get("technologies") or [])[:100],
        ])
    table = Table(rows, repeatRows=1, colWidths=[75*mm, 18*mm, 25*mm, 18*mm, 95*mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#202033")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#777777")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f7")]),
    ]))
    story.append(table)
    document.build(story)
    return buffer.getvalue()
