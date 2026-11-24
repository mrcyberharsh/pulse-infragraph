"""Visual theme for the pulse-infragraph SOC dashboard."""
from __future__ import annotations

import streamlit as st

BACKGROUND = "#09090D"
SURFACE = "#12121A"
SURFACE_RAISED = "#181823"
BORDER = "#2A2A38"
PURPLE = "#A855F7"
CYAN = "#22D3EE"
TEXT = "#F4F4F7"
MUTED = "#9696A8"


def apply_theme() -> None:
    """Apply the shared dark SOC theme without changing Streamlit behavior."""
    st.markdown(
        """
        <style>
        :root {
          color-scheme: dark;
          --pulse-bg: #09090D;
          --pulse-surface: #12121A;
          --pulse-raised: #181823;
          --pulse-border: #2A2A38;
          --pulse-purple: #A855F7;
          --pulse-cyan: #22D3EE;
          --pulse-text: #F4F4F7;
          --pulse-muted: #9696A8;
        }
        .stApp { background: var(--pulse-bg); color: var(--pulse-text); }
        [data-testid="stHeader"] { background: rgba(9,9,13,.92); }
        [data-testid="stSidebar"] {
          background: #0E0E15;
          border-right: 1px solid var(--pulse-border);
        }
        [data-testid="stSidebar"] > div { padding-top: 1.2rem; }
        h1, h2, h3 { letter-spacing: -.025em; color: var(--pulse-text); }
        h1 { font-weight: 750; }
        p, label, [data-testid="stCaptionContainer"] { color: var(--pulse-muted); }
        [data-testid="stMetric"] {
          background: linear-gradient(145deg, #171722, #111119);
          border: 1px solid var(--pulse-border);
          border-radius: 14px;
          padding: 16px 18px;
          min-height: 112px;
        }
        [data-testid="stMetricLabel"] { color: var(--pulse-muted); }
        [data-testid="stMetricValue"] { color: var(--pulse-text); }
        [data-testid="stMetricDelta"] { font-size: .78rem; }
        div.stButton > button, div.stDownloadButton > button {
          border-radius: 10px;
          border: 1px solid var(--pulse-border);
          background: #191923;
          color: var(--pulse-text);
          min-height: 42px;
          transition: border-color .15s ease, background .15s ease;
        }
        div.stButton > button:hover, div.stDownloadButton > button:hover {
          border-color: var(--pulse-purple);
          background: #21182D;
          color: white;
        }
        div.stButton > button[kind="primary"] {
          background: linear-gradient(100deg, #8B35D6, #A855F7);
          border-color: #A855F7;
          color: white;
        }
        [data-testid="stTextInput"] input,
        [data-testid="stSelectbox"] div[data-baseweb="select"] > div {
          background: #15151E;
          border-color: var(--pulse-border);
          border-radius: 10px;
        }
        [data-testid="stDataFrame"], [data-testid="stTable"] {
          border: 1px solid var(--pulse-border);
          border-radius: 12px;
          overflow: hidden;
        }
        [data-testid="stTabs"] button[aria-selected="true"] {
          color: #D8B4FE;
          border-bottom-color: var(--pulse-purple);
        }
        [data-testid="stExpander"] {
          border: 1px solid var(--pulse-border);
          border-radius: 12px;
          background: #111119;
        }
        .pulse-brand {
          font-size: 1.04rem; font-weight: 800; letter-spacing: .02em;
          color: var(--pulse-text); line-height: 1.15;
        }
        .pulse-brand span { color: var(--pulse-purple); }
        .pulse-eyebrow {
          color: var(--pulse-muted); text-transform: uppercase;
          letter-spacing: .12em; font-size: .68rem; font-weight: 700;
        }
        .pulse-panel {
          background: linear-gradient(145deg, #15151F, #101018);
          border: 1px solid var(--pulse-border);
          border-radius: 14px; padding: 18px;
        }
        .pulse-panel-title { font-size: 1rem; font-weight: 700; color: var(--pulse-text); }
        .pulse-muted { color: var(--pulse-muted); font-size: .84rem; }
        .pulse-status {
          display: inline-flex; align-items: center; gap: 7px;
          border: 1px solid #24543D; background: #10251B;
          color: #4ADE80; padding: 5px 10px; border-radius: 999px;
          font-size: .72rem; font-weight: 700; letter-spacing: .04em;
        }
        .pulse-dot { width: 7px; height: 7px; border-radius: 50%; background: #4ADE80; }
        .pulse-footer {
          color: #737386; font-size: .72rem; border-top: 1px solid var(--pulse-border);
          padding-top: 14px; margin-top: 28px;
        }
        @media (max-width: 900px) {
          .pulse-panel { padding: 13px; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
