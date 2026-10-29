# pulse-infragraph

**Community Edition v1.5.0** — open-source Attack Surface Management (ASM) and OSINT graph tooling by **Harsh Saini (MR CYBER PULSE)**. License: MIT.

> Use only for domains you own or have explicit written authorization to assess. Discovery uses public certificate-transparency data; HTTP fingerprinting sends requests to discovered hosts. Risk labels are heuristics, not vulnerability findings.

## Features in Community Edition v1.5

- **Risk Pulse Engine:** explainable 0–100 risk scores, SAFE / EXPOSED / CRITICAL levels, colors, and reasons.
- **Technology fingerprinting:** async HTTP header/body checks for Cloudflare, WordPress, AWS, Nginx, and React.
- **Timeline:** Neo4j `first_seen` / `last_seen` timestamps and assets first observed during the last 24 hours.
- **Attack-path graph:** domain → subdomain → technology / risk level with risk-aware node sizes and colors.
- **Community exports:** Nuclei target list (`subdomains.txt`), JSON report with tool credit, and CSV.
- **Cross-platform:** Python virtual environment works on Linux, macOS, and Windows.
- **Graceful database failure:** dashboard displays a warning if Neo4j is unavailable.

## Requirements

- Python 3.11+
- Docker Engine + Compose plugin (recommended for Neo4j)
- Git and pip
- Linux/macOS/Windows

## Quick start (Linux/macOS)

```bash
git clone https://github.com/mrcyberharsh/pulse-infragraph.git
cd pulse-infragraph
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env 2>/dev/null || true
docker compose up -d neo4j
streamlit run app.py
```

Open the local URL Streamlit prints. On Windows, create/activate the environment with `py -3.11 -m venv .venv`, then `.venv\\Scripts\\activate`, install requirements, and run `streamlit run app.py`.

## Docker Compose

1. Set a strong `NEO4J_PASSWORD` in your shell or `.env`.
2. Run `docker compose up --build`.
3. Visit Streamlit at `http://localhost:8501`.

Never deploy Neo4j with a default password exposed to an untrusted network. The compose file binds Neo4j ports to localhost only.

## Installer

The included `install.sh` checks common dependencies, creates a virtual environment, installs requirements, and installs a global launcher at `/usr/local/bin/pulse-infragraph`. Review the script before running it. It may require `sudo` for the global launcher. The installer does not install Docker itself.

```bash
chmod +x install.sh
./install.sh
```

## Risk model

| Signal | Points | Notes |
|---|---:|---|
| Hostname includes `dev`, `test`, `staging`, `admin`, `beta`, `internal`, or `api-dev` | +40 | Broad substring heuristic; inspect context |
| WordPress detected | +20 | Technology exposure is not itself a vulnerability |
| Open ports supplied by an authorized scanner | +5 each, max +20 | Placeholder input only; this app does not scan ports |

Scores are capped at 100. `SAFE` = 0–29, `EXPOSED` = 30–59, `CRITICAL` = 60–100. These labels prioritize review; they do not establish exploitability or absence of risk.

## Data model

- `(:Domain)-[:HAS_SUBDOMAIN]->(:Subdomain)`
- `(:Subdomain)-[:USES_TECH]->(:Tech)`
- Subdomains track `first_seen`, `last_seen`, `risk_score`, `risk_level`, `risk_color`, and `risk_reasons`.

## CLI / installer branding

`Installing pulse-infragraph by Harsh Saini (MR CYBER PULSE)`

Dashboard footer:
`pulse-infragraph v1.0.0 | Created by Harsh Saini (MR CYBER PULSE) | Open-Source ASM Tool`

The UI footer intentionally retains the requested v1.0.0 branding string while the package/readme identify this release as Community Edition v1.5.0.

## Configuration

Environment variables:
- `NEO4J_URI` (default `bolt://localhost:7687`)
- `NEO4J_USER` (default `neo4j`)
- `NEO4J_PASSWORD` (default development-only placeholder; set a strong value)

## Exports

- **Nuclei:** newline-separated discovered hostnames. This export does not run Nuclei.
- **JSON:** domain, findings, risk signals, timestamps, and tool credit.
- **CSV:** one row per asset, with score, level, reasons, and technologies.

## Project structure

```text
pulse-infragraph/
├── app.py
├── core/
│   ├── __init__.py
│   ├── engine.py
│   ├── graph.py
│   ├── risk.py
│   ├── fingerprint.py
│   └── exporter.py
├── install.sh
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## License

MIT. Copyright (c) Harsh Saini (MR CYBER PULSE).
