"""Small, safe-to-compose Streamlit components for the SOC dashboard."""
from __future__ import annotations

from html import escape
from typing import Any

import streamlit as st


def render_page_heading(title: str, subtitle: str, status: str = "LOCAL DASHBOARD") -> None:
    """Render a compact page heading and local application status."""
    left, right = st.columns([5, 1])
    with left:
        st.markdown(f'<div class="pulse-eyebrow">MR CYBER PULSE / COMMUNITY EDITION</div>', unsafe_allow_html=True)
        st.markdown(f"## {title}")
        st.caption(subtitle)
    with right:
        st.markdown(
            f'<div style="text-align:right;padding-top:10px">'
            f'<span class="pulse-status"><span class="pulse-dot"></span>{escape(status)}</span></div>',
            unsafe_allow_html=True,
        )


def render_panel_title(title: str, description: str | None = None) -> None:
    """Render a consistent section title."""
    st.markdown(f'<div class="pulse-panel-title">{escape(title)}</div>', unsafe_allow_html=True)
    if description:
        st.markdown(f'<div class="pulse-muted">{escape(description)}</div>', unsafe_allow_html=True)


def render_risk_gauge(score: int | None, label: str = "Aggregate heuristic risk") -> None:
    """Render a CSS gauge; a missing score is shown as unavailable, never as zero."""
    if score is None:
        st.markdown(
            '<div class="pulse-panel"><div class="pulse-panel-title">Risk posture</div>'
            '<div class="pulse-muted">Run a scan to calculate a risk score.</div></div>',
            unsafe_allow_html=True,
        )
        return
    bounded = max(0, min(100, int(score)))
    color = "#22C55E" if bounded < 30 else "#F59E0B" if bounded < 60 else "#EF4444"
    st.markdown(
        f"""
        <div class="pulse-panel">
          <div class="pulse-panel-title">Risk posture</div>
          <div class="pulse-muted">{escape(label)}</div>
          <div style="display:flex;align-items:center;gap:18px;margin-top:18px">
            <div style="width:104px;height:104px;border-radius:50%;
              background:conic-gradient({color} {bounded}%, #30303C 0);
              display:grid;place-items:center;flex:none">
              <div style="width:78px;height:78px;border-radius:50%;background:#15151F;
                display:grid;place-items:center;color:#F4F4F7;font-size:1.35rem;font-weight:800">
                {bounded}
              </div>
            </div>
            <div><div style="font-size:1.05rem;font-weight:700;color:{color}">
              {"SAFE" if bounded < 30 else "EXPOSED" if bounded < 60 else "CRITICAL"}
            </div><div class="pulse-muted">Heuristic score / 100</div></div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def asset_table_rows(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert scan records to a stable, display-only table shape."""
    rows: list[dict[str, Any]] = []
    for asset in assets:
        risk = asset.get("risk") or {}
        fingerprint = asset.get("fingerprint") or {}
        rows.append(
            {
                "Asset": asset.get("subdomain") or "Unknown",
                "Risk": risk.get("score", "—"),
                "Severity": risk.get("level", "UNKNOWN"),
                "HTTP": fingerprint.get("status") or "—",
                "Technologies": ", ".join(fingerprint.get("technologies") or []) or "—",
            }
        )
    return rows
