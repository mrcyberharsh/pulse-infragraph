"""Streamlit dashboard for pulse-infragraph Community Edition."""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import streamlit as st
from streamlit_agraph import Config, Edge, Node, agraph

from core.engine import scan_domain
from core.exporter import export_bugbounty_json, export_csv, export_nuclei_txt
from core.graph import GraphStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

BG = "#0a0a0f"
PURPLE = "#a855f7"
CYAN = "#22d3ee"
FOOTER = "pulse-infragraph v1.0.0 | Created by Harsh Saini (MR CYBER PULSE) | Open-Source ASM Tool"
HISTORY_PATH = Path(".pulse-infragraph-history.json")
DEFAULT_RISK_WEIGHTS = {"keyword": 40, "wordpress": 20, "port": 5}


def load_scan_history() -> list[dict[str, Any]]:
    """Load recent scan results from a local JSON file."""
    if not HISTORY_PATH.exists():
        return []
    try:
        with HISTORY_PATH.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if isinstance(payload, list):
            return payload
    except (OSError, json.JSONDecodeError):
        logger.warning("Could not read scan history; starting from empty state.")
    return []


def save_scan_history(entry: dict[str, Any]) -> None:
    """Persist a compact scan summary for quick historical review."""
    history = load_scan_history()
    history.insert(0, entry)
    history = history[:20]
    with HISTORY_PATH.open("w", encoding="utf-8") as handle:
        json.dump(history, handle, indent=2, ensure_ascii=False)


st.set_page_config(page_title="pulse-infragraph | MR CYBER PULSE", page_icon="🕸️", layout="wide")
st.markdown(f"""
<style>
.stApp {{ background: {BG}; color: #e5e7eb; }}
[data-testid="stSidebar"] {{ background: #11111b; border-right: 1px solid {PURPLE}; }}
h1,h2,h3 {{ color: {CYAN}; }}
div[data-testid="stMetric"] {{ background:#11111b; border:1px solid {PURPLE}; padding:14px; border-radius:12px; }}
.pulse-footer {{ color:#9ca3af; font-size:0.78rem; border-top:1px solid {PURPLE}; padding-top:12px; margin-top:28px; }}
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def get_graph() -> GraphStore:
    return GraphStore()


graph = get_graph()
with st.sidebar:
    st.image("logo.png", width=150) if __import__("pathlib").Path("logo.png").exists() else st.markdown(f"## 🕸️ <span style='color:{PURPLE}'>MR CYBER PULSE</span>", unsafe_allow_html=True)
    st.markdown("### pulse-infragraph")
    st.caption("Community Edition v1.5.0")
    st.caption("Contact: YOUR_PUBLIC_EMAIL@example.com")
    st.markdown("---")
    st.markdown("### Risk tuning")
    keyword_weight = st.slider("Hostname keyword weight", 0, 100, DEFAULT_RISK_WEIGHTS["keyword"], key="keyword_weight")
    wordpress_weight = st.slider("WordPress weight", 0, 100, DEFAULT_RISK_WEIGHTS["wordpress"], key="wordpress_weight")
    port_weight = st.slider("Open port weight", 0, 100, DEFAULT_RISK_WEIGHTS["port"], key="port_weight")
    scan_settings = {"keyword": keyword_weight, "wordpress": wordpress_weight, "port": port_weight}
    st.markdown("---")
    st.caption("Use only on domains you own or are explicitly authorized to assess.")
    st.markdown(f"<div class='pulse-footer'>{FOOTER}</div>", unsafe_allow_html=True)

    history = load_scan_history()
    if history:
        st.markdown("### Recent scans")
        for item in history[:5]:
            st.caption(f"{item.get('domain', 'unknown')} · {item.get('timestamp', '')}")

st.title("🕸️ pulse-infragraph")
st.caption("Attack Surface Management · OSINT Graph · Community Edition")
domain_input = st.text_input("Authorized root domain", placeholder="example.com")
col_scan, col_refresh = st.columns([1, 1])
with col_scan:
    scan_clicked = st.button("🚀 Discover & Analyze", type="primary", use_container_width=True)
with col_refresh:
    refresh_clicked = st.button("↻ Refresh Graph Data", use_container_width=True)

if not graph.available:
    st.warning("Neo4j is offline or unreachable. Scanning can still run, but graph persistence and saved-asset views are unavailable. Check NEO4J_URI, NEO4J_USER, and NEO4J_PASSWORD.")

if scan_clicked:
    trimmed_domain = domain_input.strip()
    if not trimmed_domain:
        st.warning("Please enter a valid root domain such as example.com.")
    else:
        try:
            with st.spinner("Discovering public certificate records and fingerprinting responsive hosts…"):
                result = asyncio.run(scan_domain(trimmed_domain, graph if graph.available else None, weights=scan_settings))
            result.setdefault("scan_id", uuid4().hex[:8])
            result["scan_settings"] = scan_settings
            result["timestamp"] = datetime.now(timezone.utc).isoformat()
            st.session_state["last_result"] = result
            save_scan_history({
                "scan_id": result.get("scan_id"),
                "domain": result.get("domain"),
                "timestamp": result.get("timestamp"),
                "asset_count": result.get("count", 0),
                "settings": scan_settings,
            })
            st.success(f"Analysis complete: {result['count']} assets processed.")
        except ValueError as exc:
            st.error(str(exc))
        except Exception as exc:
            logger.exception("Scan failed")
            st.error(f"Could not run analysis: {exc}")

data: dict[str, Any] = st.session_state.get("last_result", {"domain": "", "assets": []})
if refresh_clicked and graph.available:
    try:
        rows = graph.get_assets()
        data = {"domain": "", "assets": [
            {"domain": "", "subdomain": row["name"], "risk": {"score": row.get("score") or 0,
             "level": row.get("level") or "SAFE", "color": row.get("color") or "#22c55e",
             "reasons": row.get("reasons") or []},
             "fingerprint": {"technologies": row.get("technologies") or []}}
            for row in rows
        ]}
        st.session_state["last_result"] = data
    except Exception as exc:
        st.error(f"Unable to load saved assets: {exc}")

assets = data.get("assets", [])
critical = sum(1 for a in assets if a.get("risk", {}).get("level") == "CRITICAL")
exposed = sum(1 for a in assets if a.get("risk", {}).get("level") == "EXPOSED")
m1, m2, m3 = st.columns(3)
m1.metric("Total Subdomains", len(assets))
m2.metric("Critical Count", critical)
m3.metric("Exposed Count", exposed)

if graph.available:
    try:
        timeline = graph.get_timeline(24)
        st.info(f"🔥 {len(timeline)} NEW assets in last 24h")
    except Exception as exc:
        logger.warning("Timeline query failed: %s", exc)
        st.caption("Timeline is temporarily unavailable.")
else:
    st.caption("🔥 New-assets timeline becomes available when Neo4j is connected.")

if assets:
    st.subheader("Attack Path Visualization")
    nodes: list[Node] = []
    edges: list[Edge] = []
    root_name = data.get("domain") or "Saved Assets"
    nodes.append(Node(id=root_name, label=root_name, size=35, color=PURPLE, shape="diamond"))
    seen_tech: set[str] = set()
    seen_risk: set[str] = set()
    for asset in assets:
        host = asset.get("subdomain", asset.get("name", "unknown"))
        risk = asset.get("risk", {})
        color = risk.get("color", "#22c55e")
        score = int(risk.get("score", 0) or 0)
        nodes.append(Node(id=host, label=f"{host}\n{score}/100", size=max(15, min(50, 15 + score // 3)), color=color))
        edges.append(Edge(source=root_name, target=host, color=color, label="asset"))
        for tech in asset.get("fingerprint", {}).get("technologies", []):
            tech_id = f"tech:{tech}"
            if tech not in seen_tech:
                nodes.append(Node(id=tech_id, label=tech, size=18, color=CYAN))
                seen_tech.add(tech)
            edges.append(Edge(source=host, target=tech_id, color=color, label="USES_TECH"))
        level = risk.get("level", "SAFE")
        level_id = f"risk:{level}"
        if level not in seen_risk:
            nodes.append(Node(id=level_id, label=level, size=20, color=color, shape="hexagon"))
            seen_risk.add(level)
        edges.append(Edge(source=host, target=level_id, color=color, label="risk"))
    config = Config(width=1100, height=600, directed=True, physics=True, hierarchical=False,
                    nodeHighlightBehavior=True, highlightColor=CYAN, collapsible=True)
    agraph(nodes=nodes, edges=edges, config=config)

    with st.expander("Risk Details", expanded=critical > 0 or exposed > 0):
        risky = [a for a in assets if a.get("risk", {}).get("level") in {"EXPOSED", "CRITICAL"}]
        if not risky:
            st.success("No EXPOSED or CRITICAL heuristic risk signals were detected.")
        for asset in risky:
            risk = asset.get("risk", {})
            st.markdown(f"**{asset.get('subdomain', asset.get('name'))}** — :orange[{risk.get('level')}] · {risk.get('score')}/100")
            for reason in risk.get("reasons", []):
                st.write(f"- {reason}")
            techs = asset.get("fingerprint", {}).get("technologies", asset.get("technologies", []))
            if techs:
                st.caption("Technologies: " + ", ".join(techs))

    st.subheader("Community Exports")
    c1, c2, c3 = st.columns(3)
    hosts = [a.get("subdomain", a.get("name", "")) for a in assets]
    with c1:
        st.download_button("⬇ Download for Nuclei", export_nuclei_txt(hosts), file_name="subdomains.txt", mime="text/plain", use_container_width=True)
    with c2:
        st.download_button("⬇ Download JSON Report", export_bugbounty_json(data), file_name="pulse-infragraph-report.json", mime="application/json", use_container_width=True)
    with c3:
        st.download_button("⬇ Export CSV", export_csv(data), file_name="pulse-infragraph-assets.csv", mime="text/csv", use_container_width=True)
else:
    st.info("Enter an authorized domain and select **Discover & Analyze** to begin.")

st.markdown(f"<div class='pulse-footer'>{FOOTER}</div>", unsafe_allow_html=True)

