"""Streamlit dashboard for pulse-infragraph Community Edition."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import streamlit as st
from streamlit_agraph import Config, Edge, Node, agraph

from core.engine import normalize_domain, scan_domain
from core.exporter import export_bugbounty_json, export_csv, export_nuclei_txt, export_pdf
from core.graph import GraphStore
from core.history import compare_scans, load_history, save_scan

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

BG = "#0a0a0f"
PURPLE = "#a855f7"
CYAN = "#22d3ee"
FOOTER = "pulse-infragraph v1.0.0 | Created by Harsh Saini (MR CYBER PULSE) | Open-Source ASM Tool"
DEFAULT_RISK_WEIGHTS = {"keyword": 40, "wordpress": 20, "port": 5}


@st.cache_resource
def get_graph() -> GraphStore:
    return GraphStore()


def render_risk_controls() -> dict[str, int]:
    st.markdown("### Risk tuning")
    return {
        "keyword": st.slider("Hostname keyword weight", 0, 100, 40, key="keyword_weight"),
        "wordpress": st.slider("WordPress weight", 0, 100, 20, key="wordpress_weight"),
        "port": st.slider("Open-port signal weight", 0, 100, 5, key="port_weight"),
    }


def render_history(history: list[dict[str, Any]], domain: str) -> None:
    """Show trend information for the currently selected domain."""
    relevant = [item for item in history if item.get("domain") == domain]
    if not relevant:
        st.caption("Run a scan to begin building a local risk and asset history.")
        return
    st.subheader("Risk trend")
    chart_rows = []
    for item in reversed(relevant):
        chart_rows.append({
            "Scan": item.get("timestamp", "")[:19],
            "Assets": item.get("asset_count", 0),
            "Critical": item.get("critical_count", 0),
            "Exposed": item.get("exposed_count", 0),
        })
    st.line_chart(chart_rows, x="Scan", y=["Assets", "Critical", "Exposed"])
    delta = compare_scans(relevant)
    if delta:
        c1, c2, c3 = st.columns(3)
        c1.metric("New assets", delta["new_assets"])
        c2.metric("Removed assets", delta["removed_assets"])
        c3.metric("Risk score change", delta["risk_score_delta"])
    with st.expander("Previous scan snapshots"):
        for item in relevant[:10]:
            st.caption(
                f"{item.get('timestamp', 'unknown')} · "
                f"{item.get('asset_count', 0)} assets · "
                f"{item.get('critical_count', 0)} critical"
            )


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

graph = get_graph()
history = load_history()
with st.sidebar:
    if Path("logo.png").exists():
        st.image("logo.png", width=150)
    else:
        st.markdown(f"## 🕸️ <span style='color:{PURPLE}'>MR CYBER PULSE</span>", unsafe_allow_html=True)
    st.markdown("### pulse-infragraph")
    st.caption("Community Edition · asset inventory and risk trends")
    st.markdown("---")
    scan_settings = render_risk_controls()
    st.markdown("---")
    st.caption("Only assess domains you own or are explicitly authorized to review.")
    st.markdown(f"<div class='pulse-footer'>{FOOTER}</div>", unsafe_allow_html=True)

st.title("🕸️ pulse-infragraph")
st.caption("Attack Surface Management · OSINT Graph · Community Edition")
domain_input = st.text_input("Authorized root domain", placeholder="example.com")
col_scan, col_refresh = st.columns([1, 1])
with col_scan:
    scan_clicked = st.button("🚀 Discover & Analyze", type="primary", use_container_width=True)
with col_refresh:
    refresh_clicked = st.button("↻ Refresh Graph Data", use_container_width=True)

if not graph.available:
    st.warning(
        "Neo4j is offline. Passive discovery and local history still work; "
        "graph persistence is unavailable. Configure NEO4J_URI, NEO4J_USER, "
        "and NEO4J_PASSWORD to enable it."
    )

if scan_clicked:
    try:
        domain = normalize_domain(domain_input)
        with st.spinner("Reading public certificate records and checking authorized hosts…"):
            result = asyncio.run(
                scan_domain(domain, graph if graph.available else None, weights=scan_settings)
            )
        result["scan_id"] = uuid4().hex[:8]
        result["scan_settings"] = scan_settings
        result["timestamp"] = datetime.now(timezone.utc).isoformat()
        st.session_state["last_result"] = result
        save_scan(result)
        st.success(f"Analysis complete: {result['count']} assets processed.")
        history = load_history()
    except ValueError as exc:
        st.error(str(exc))
    except Exception as exc:
        logger.exception("Scan failed")
        st.error(f"Could not run analysis: {exc}")

data: dict[str, Any] = st.session_state.get("last_result", {"domain": "", "assets": []})
if refresh_clicked and graph.available:
    try:
        rows = graph.get_assets()
        data = {
            "domain": domain_input.strip(),
            "assets": [
                {
                    "domain": domain_input.strip(),
                    "subdomain": row["name"],
                    "risk": {
                        "score": row.get("score") or 0,
                        "level": row.get("level") or "SAFE",
                        "color": row.get("color") or "#22c55e",
                        "reasons": row.get("reasons") or [],
                    },
                    "fingerprint": {"technologies": row.get("technologies") or []},
                }
                for row in rows
            ],
        }
        st.session_state["last_result"] = data
    except Exception as exc:
        st.error(f"Unable to load saved assets: {exc}")

assets = data.get("assets", [])
critical = sum(1 for asset in assets if asset.get("risk", {}).get("level") == "CRITICAL")
exposed = sum(1 for asset in assets if asset.get("risk", {}).get("level") == "EXPOSED")
m1, m2, m3 = st.columns(3)
m1.metric("Total assets", len(assets))
m2.metric("Critical signals", critical)
m3.metric("Exposed signals", exposed)

render_history(history, data.get("domain", ""))

if graph.available:
    try:
        timeline = graph.get_timeline(24)
        st.info(f"🕒 {len(timeline)} assets first observed in the last 24 hours.")
    except Exception:
        logger.exception("Neo4j timeline query failed")

if assets:
    st.subheader("Asset relationship graph")
    nodes: list[Node] = []
    edges: list[Edge] = []
    root_name = data.get("domain") or "Saved Assets"
    nodes.append(Node(id=root_name, label=root_name, size=35, color=PURPLE, shape="diamond"))
    seen_tech: set[str] = set()
    for asset in assets:
        host = asset.get("subdomain", "unknown")
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
    agraph(
        nodes=nodes, edges=edges,
        config=Config(
            width=1100, height=600, directed=True, physics=True,
            hierarchical=False, nodeHighlightBehavior=True,
            highlightColor=CYAN, collapsible=True,
        ),
    )

    with st.expander("Risk details", expanded=critical > 0 or exposed > 0):
        risky = [a for a in assets if a.get("risk", {}).get("level") in {"EXPOSED", "CRITICAL"}]
        if not risky:
            st.success("No configured heuristic risk signals detected. This is not a security guarantee.")
        for asset in risky:
            risk = asset.get("risk", {})
            st.markdown(f"**{asset.get('subdomain')}** — {risk.get('level')} · {risk.get('score')}/100")
            for reason in risk.get("reasons", []):
                st.write(f"- {reason}")

    st.subheader("Reports and exports")
    hosts = [asset.get("subdomain", "") for asset in assets]
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.download_button("Download host list", export_nuclei_txt(hosts), "subdomains.txt", "text/plain", use_container_width=True)
    with c2:
        st.download_button("Download JSON", export_bugbounty_json(data), "pulse-infragraph-report.json", "application/json", use_container_width=True)
    with c3:
        st.download_button("Download CSV", export_csv(data), "pulse-infragraph-assets.csv", "text/csv", use_container_width=True)
    with c4:
        st.download_button("Download PDF", export_pdf(data), "pulse-infragraph-report.pdf", "application/pdf", use_container_width=True)
else:
    st.info("Enter a domain you are authorized to assess and select **Discover & Analyze**.")

st.markdown(f"<div class='pulse-footer'>{FOOTER}</div>", unsafe_allow_html=True)
