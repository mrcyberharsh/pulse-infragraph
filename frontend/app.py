# Copyright (c) 2026 MR CYBER PULSE
# SPDX-License-Identifier: GPL-3.0-or-later

"""SOC-style Streamlit dashboard for pulse-infragraph Community Edition."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import streamlit as st
from streamlit_agraph import Config, Edge, Node, agraph

from backend.core.engine import normalize_domain, scan_domain
from backend.core.exporter import export_bugbounty_json, export_csv, export_nuclei_txt, export_pdf
from backend.core.graph import GraphStore
from backend.core.history import compare_scans, load_history, save_scan
from frontend.ui.components import asset_table_rows, render_page_heading, render_panel_title, render_risk_gauge
from frontend.ui.theme import CYAN, PURPLE, apply_theme

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

FOOTER = "pulse-infragraph v1.0.0 | Created by Harsh Saini (MR CYBER PULSE) | Open-Source ASM Tool"
DEFAULT_RISK_WEIGHTS = {"keyword": 40, "wordpress": 20, "port": 5}


@st.cache_resource
def get_graph() -> GraphStore:
    """Create one shared optional Neo4j connection for the Streamlit process."""
    return GraphStore()


def render_risk_controls() -> dict[str, int]:
    """Render sidebar controls for the existing heuristic risk model."""
    st.markdown("### Risk tuning")
    return {
        "keyword": st.slider("Hostname keyword weight", 0, 100, 40, key="keyword_weight"),
        "wordpress": st.slider("WordPress weight", 0, 100, 20, key="wordpress_weight"),
        "port": st.slider("Open-port signal weight", 0, 100, 5, key="port_weight"),
    }


def render_history(history: list[dict[str, Any]], domain: str) -> None:
    """Show saved local scan history for the selected domain."""
    relevant = [item for item in history if item.get("domain") == domain]
    if not relevant:
        st.info("No saved scans for this domain yet. Run an authorized scan to build history.")
        return
    st.subheader("Asset and risk trend")
    chart_rows = [
        {
            "Scan": item.get("timestamp", "")[:19],
            "Assets": item.get("asset_count", 0),
            "Critical": item.get("critical_count", 0),
            "Exposed": item.get("exposed_count", 0),
        }
        for item in reversed(relevant)
    ]
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


def build_graph(assets: list[dict[str, Any]], root_name: str) -> tuple[list[Node], list[Edge]]:
    """Build a graph from real scan records; no synthetic relationships are added."""
    nodes: list[Node] = [Node(id=root_name, label=root_name, size=34, color=PURPLE, shape="diamond")]
    edges: list[Edge] = []
    seen_hosts: set[str] = {root_name}
    seen_tech: set[str] = set()
    for asset in assets:
        host = str(asset.get("subdomain") or "unknown")
        if host not in seen_hosts:
            risk = asset.get("risk") or {}
            color = risk.get("color", "#22C55E")
            score = int(risk.get("score", 0) or 0)
            nodes.append(
                Node(
                    id=host,
                    label=f"{host}\n{score}/100",
                    size=max(16, min(44, 16 + score // 4)),
                    color=color,
                )
            )
            edges.append(Edge(source=root_name, target=host, color=color, label="asset"))
            seen_hosts.add(host)
        for technology in (asset.get("fingerprint") or {}).get("technologies", []):
            tech = str(technology)
            tech_id = f"tech:{tech}"
            if tech_id not in seen_tech:
                nodes.append(Node(id=tech_id, label=tech, size=18, color=CYAN))
                seen_tech.add(tech_id)
            edges.append(Edge(source=host, target=tech_id, color=CYAN, label="uses"))
    return nodes, edges


def render_network_map(assets: list[dict[str, Any]], domain: str) -> None:
    """Render the existing asset-to-technology graph with supporting inventory."""
    if not assets:
        st.info("The network map will appear after an authorized scan discovers assets.")
        return
    left, center, right = st.columns([1.15, 2.5, 1.15], gap="medium")
    with left:
        render_panel_title("Discovered assets", f"{len(assets)} records in this scan")
        query = st.text_input("Filter assets", placeholder="Search hostname…", key="network_filter")
        filtered = [
            asset for asset in assets
            if query.lower() in str(asset.get("subdomain", "")).lower()
        ]
        for asset in filtered[:18]:
            risk = asset.get("risk") or {}
            st.markdown(
                f"**{asset.get('subdomain', 'Unknown')}**  "
                f"<span style='color:{risk.get('color', '#22C55E')};font-size:.78rem'>"
                f"{risk.get('level', 'SAFE')} · {risk.get('score', 0)}/100</span>",
                unsafe_allow_html=True,
            )
            st.caption(
                f"{(asset.get('fingerprint') or {}).get('status') or 'No HTTP response'} · "
                f"{', '.join((asset.get('fingerprint') or {}).get('technologies') or []) or 'No fingerprint'}"
            )
            st.divider()
        if len(filtered) > 18:
            st.caption(f"Showing 18 of {len(filtered)} matching assets.")
    with center:
        render_panel_title("Network map", "Select the graph nodes to explore discovered relationships")
        nodes, edges = build_graph(assets, domain or "Saved Assets")
        agraph(
            nodes=nodes,
            edges=edges,
            config=Config(
                width="100%",
                height=620,
                directed=True,
                physics=True,
                hierarchical=False,
                nodeHighlightBehavior=True,
                highlightColor=CYAN,
                collapsible=True,
            ),
        )
    with right:
        render_panel_title("Asset details", "Choose an asset to inspect its scan record")
        host_options = [str(asset.get("subdomain") or "Unknown") for asset in assets]
        selected_host = st.selectbox("Selected asset", host_options, key="network_selected_asset")
        selected = next(
            (asset for asset in assets if str(asset.get("subdomain") or "Unknown") == selected_host),
            assets[0],
        )
        risk = selected.get("risk") or {}
        fingerprint = selected.get("fingerprint") or {}
        st.markdown(f"### {selected_host}")
        st.metric("Risk score", f"{risk.get('score', 0)}/100", risk.get("level", "UNKNOWN"))
        st.write("**HTTP status**")
        st.write(fingerprint.get("status") or "Not available")
        st.write("**Technologies**")
        technologies = fingerprint.get("technologies") or []
        st.write(", ".join(technologies) if technologies else "No technologies identified")
        st.write("**Risk reasons**")
        for reason in risk.get("reasons") or ["No configured heuristic signals."]:
            st.caption(f"• {reason}")


st.set_page_config(
    page_title="pulse-infragraph | MR CYBER PULSE",
    page_icon="🕸️",
    layout="wide",
    initial_sidebar_state="expanded",
)
apply_theme()

graph = get_graph()
history = load_history()

with st.sidebar:
    logo_path = Path(__file__).resolve().parents[1] / "logo.png"
    if logo_path.exists():
        st.image(str(logo_path), width=170)
    else:
        st.markdown('<div class="pulse-brand">PULSE <span>INFRAGRAPH</span></div>', unsafe_allow_html=True)
    st.caption("SECURITY OPERATIONS CENTER")
    st.divider()
    page = st.radio(
        "WORKSPACE",
        ["Overview", "Asset Discovery", "Network Map", "Risk Intelligence", "Scan History", "Reports"],
        label_visibility="visible",
    )
    st.divider()
    with st.expander("Scan configuration", expanded=True):
        domain_input = st.text_input("Authorized root domain", placeholder="example.com")
        scan_settings = render_risk_controls()
        scan_clicked = st.button("＋  Discover & Analyze", type="primary", use_container_width=True)
        refresh_clicked = st.button("↻  Refresh Graph Data", use_container_width=True)
    st.caption("Only assess domains you own or are explicitly authorized to review.")
    if graph.available:
        st.markdown('<span class="pulse-status"><span class="pulse-dot"></span>NEO4J CONNECTED</span>', unsafe_allow_html=True)
    else:
        st.caption("○ Neo4j optional · not connected")

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
if refresh_clicked:
    if not graph.available:
        st.warning("Neo4j is not connected. Local scan results and history remain available.")
    else:
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
                            "color": row.get("color") or "#22C55E",
                            "reasons": row.get("reasons") or [],
                        },
                        "fingerprint": {"technologies": row.get("technologies") or []},
                    }
                    for row in rows
                ],
            }
            st.session_state["last_result"] = data
        except Exception as exc:
            logger.exception("Could not refresh graph data")
            st.error(f"Unable to load saved assets: {exc}")

assets = data.get("assets", [])
domain = data.get("domain", "")
critical = sum(1 for asset in assets if (asset.get("risk") or {}).get("level") == "CRITICAL")
exposed = sum(1 for asset in assets if (asset.get("risk") or {}).get("level") == "EXPOSED")
scores = [int((asset.get("risk") or {}).get("score", 0) or 0) for asset in assets]
aggregate_risk = round(sum(scores) / len(scores)) if scores else None

if page == "Overview":
    render_page_heading("Security Overview", "Your authorized external attack-surface inventory at a glance.")
    st.markdown("")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("TOTAL ASSETS", len(assets))
    m2.metric("CRITICAL SIGNALS", critical)
    m3.metric("EXPOSED SIGNALS", exposed)
    m4.metric("SAVED SCANS", len([item for item in history if not domain or item.get("domain") == domain]))
    st.markdown("")
    left, right = st.columns([1.65, 1], gap="large")
    with left:
        with st.container(border=True):
            render_panel_title("Asset discovery", "Current scan inventory and detected technologies")
            if assets:
                st.dataframe(asset_table_rows(assets), use_container_width=True, hide_index=True)
            else:
                st.info("No scan data yet. Enter an authorized root domain in Scan configuration to begin.")
    with right:
        render_risk_gauge(aggregate_risk, "Average heuristic risk across current assets")
        st.markdown("")
        with st.container(border=True):
            render_panel_title("Risk distribution")
            st.metric("Critical", critical)
            st.metric("Exposed", exposed)
            st.metric("Safe / no configured signals", max(0, len(assets) - critical - exposed))
    st.markdown("")
    with st.container(border=True):
        render_panel_title("Recent activity", "Latest locally saved scan snapshots")
        recent = [item for item in history if not domain or item.get("domain") == domain][:5]
        if recent:
            st.dataframe(
                [
                    {
                        "Domain": item.get("domain", ""),
                        "Timestamp": item.get("timestamp", ""),
                        "Assets": item.get("asset_count", 0),
                        "Critical": item.get("critical_count", 0),
                        "Exposed": item.get("exposed_count", 0),
                    }
                    for item in recent
                ],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.caption("No scan activity has been saved yet.")

elif page == "Asset Discovery":
    render_page_heading("Asset Discovery", "Search and review assets returned by the current scan.")
    search = st.text_input("Search discovered assets", placeholder="Filter by hostname or technology")
    filtered_assets = [
        asset for asset in assets
        if search.lower() in str(asset.get("subdomain", "")).lower()
        or search.lower() in ", ".join((asset.get("fingerprint") or {}).get("technologies") or []).lower()
    ]
    st.caption(f"{len(filtered_assets)} matching assets · {len(assets)} total in current result")
    if filtered_assets:
        st.dataframe(asset_table_rows(filtered_assets), use_container_width=True, hide_index=True)
    else:
        st.info("No matching assets. Run an authorized scan or adjust the search.")

elif page == "Network Map":
    render_page_heading("Network Intelligence", "Explore domain, discovered hosts and detected technology relationships.")
    render_network_map(assets, domain)

elif page == "Risk Intelligence":
    render_page_heading("Risk Intelligence", "Explainable heuristic signals for prioritizing manual review.")
    m1, m2, m3 = st.columns(3)
    m1.metric("Critical", critical)
    m2.metric("Exposed", exposed)
    m3.metric("Average score", f"{aggregate_risk}/100" if aggregate_risk is not None else "—")
    if not assets:
        st.info("Run an authorized scan to calculate risk indicators.")
    else:
        risky = [asset for asset in assets if (asset.get("risk") or {}).get("level") in {"EXPOSED", "CRITICAL"}]
        if not risky:
            st.success("No configured heuristic signals detected. This is not a security guarantee.")
        for asset in risky:
            risk = asset.get("risk") or {}
            with st.container(border=True):
                st.markdown(f"**{asset.get('subdomain')}**")
                st.progress(max(0, min(100, int(risk.get("score", 0) or 0))) / 100)
                st.caption(f"{risk.get('level')} · {risk.get('score')}/100")
                for reason in risk.get("reasons") or []:
                    st.write(f"• {reason}")
    st.caption("Risk scores are heuristic indicators, not proof that a host is vulnerable or safe.")

elif page == "Scan History":
    render_page_heading("Scan History", "Compare saved snapshots and review changes over time.")
    render_history(history, domain)
    if history:
        with st.expander("All saved scan records"):
            st.dataframe(
                [
                    {
                        "Domain": item.get("domain", ""),
                        "Timestamp": item.get("timestamp", ""),
                        "Assets": item.get("asset_count", 0),
                        "Critical": item.get("critical_count", 0),
                        "Exposed": item.get("exposed_count", 0),
                    }
                    for item in history
                ],
                use_container_width=True,
                hide_index=True,
            )

elif page == "Reports":
    render_page_heading("Reports & Exports", "Export the current scan result in portable formats.")
    if not assets:
        st.info("No current scan result to export. Run an authorized scan first.")
    else:
        hosts = [asset.get("subdomain", "") for asset in assets]
        st.caption(f"Report scope: {domain} · {len(assets)} assets")
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.download_button("Download host list", export_nuclei_txt(hosts), "subdomains.txt", "text/plain", use_container_width=True)
        with c2:
            st.download_button("Download JSON", export_bugbounty_json(data), "pulse-infragraph-report.json", "application/json", use_container_width=True)
        with c3:
            st.download_button("Download CSV", export_csv(data), "pulse-infragraph-assets.csv", "text/csv", use_container_width=True)
        with c4:
            st.download_button("Download PDF", export_pdf(data), "pulse-infragraph-report.pdf", "application/pdf", use_container_width=True)

st.markdown(f'<div class="pulse-footer">{FOOTER}</div>', unsafe_allow_html=True)
