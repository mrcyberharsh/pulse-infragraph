# pulse-infragraph

<p align="center">
  <img src="logo.png" alt="pulse-infragraph logo" width="620" />
</p>

<p align="center">
  <strong>Community Edition</strong> · Open-source attack surface management for authorized security research
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white" />
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green.svg" />
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-0ea5e9" />
  <img alt="Neo4j" src="https://img.shields.io/badge/Neo4j-Graph-4581C3?logo=neo4j&logoColor=white" />
</p>

pulse-infragraph is a lightweight, beginner-friendly attack surface management (ASM) tool that helps you discover public assets, identify exposed technologies, rank risk signals, and export friendly security outputs for authorized domains.

## Why this project

- Passive subdomain discovery via certificate transparency
- Quick HTTP(S) fingerprinting for common technology stacks
- Explainable risk scoring with clear reasons
- Neo4j-backed graph persistence for saved asset views and history
- Nuclei, JSON, and CSV export flows for standard workflows
- Designed with responsible-use guardrails and explicit domain validation

## Features

- Passive discovery of subdomains for a root domain
- HTTP/HTTPS fingerprinting for Cloudflare, WordPress, Nginx, AWS, React, and more
- Human-readable risk scores and reasons
- Neo4j graph mapping for domain → asset → technology relationships
- Timeline support for assets newly observed in the last 24 hours
- Downloadable exports for bug bounty and recon workflows
- Configurable risk tuning from the dashboard
- CLI mode for terminal-only execution

## Responsible use

This tool is intended for education, authorized security research, and bug bounty work only.

- Only scan domains you own or are explicitly authorized to test
- Respect rate limits and upstream service behavior
- Treat all heuristic results as informational only
- Do not use this tool against systems without permission

## Requirements

- Python 3.11+
- Git
- Internet access for certificate transparency and HTTP checks
- Optional but recommended: Neo4j running locally via Docker

## Quick start

### 1) Clone the repository

```bash
git clone https://github.com/mrcyberharsh/pulse-infragraph.git
cd pulse-infragraph
```

### 2) Create a virtual environment

#### Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

#### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3) Start Neo4j (recommended)

```bash
docker compose up -d neo4j
```

### 4) Set environment variables

#### Linux/macOS

```bash
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="replace-with-a-strong-password"
```

#### Windows PowerShell

```powershell
$env:NEO4J_URI="bolt://localhost:7687"
$env:NEO4J_USER="neo4j"
$env:NEO4J_PASSWORD="replace-with-a-strong-password"
```

### 5) Run the app

```bash
streamlit run app.py
```

Open the local Streamlit URL and enter an authorized domain such as `example.com`.

## CLI usage

Run a scan without the dashboard:

```bash
python cli.py example.com
```

Example output:

```json
{
  "domain": "example.com",
  "count": 12,
  "assets": [
    {
      "subdomain": "www.example.com",
      "risk": {
        "score": 20,
        "level": "SAFE",
        "reasons": [
          "No configured risk signals detected; this is not a security guarantee."
        ]
      }
    }
  ]
}
```

## Risk model

The project uses explainable heuristics rather than hidden scoring logic.

Current signals include:

- risky hostname keywords such as `dev`, `test`, `staging`, `admin`, `beta`, `internal`, `api-dev`
- WordPress detection
- optional port-based exposure signals supplied by an authorized scanner

Risk levels:

- SAFE: 0–29
- EXPOSED: 30–59
- CRITICAL: 60–100

## Export formats

The app can export:

- `subdomains.txt` — one hostname per line for a Nuclei target list
- `pulse-infragraph-report.json` — structured JSON report with metadata
- `pulse-infragraph-assets.csv` — spreadsheet-friendly row data

## Project structure

```text
pulse-infragraph/
├── app.py
├── cli.py
├── core/
│   ├── engine.py
│   ├── exporter.py
│   ├── fingerprint.py
│   ├── graph.py
│   └── risk.py
├── logo.png
├── requirements.txt
├── README.md
├── LICENSE
├── docker-compose.yml
├── Dockerfile
├── install.sh
└── .pulse-infragraph-history.json  # generated locally
```

## Troubleshooting

### Neo4j offline

```bash
docker ps
docker compose up -d neo4j
docker compose logs neo4j
```

### No subdomains found

- verify the domain is valid and not a URL or wildcard
- certificate transparency data may be incomplete or delayed
- retry later if upstream services are temporarily unavailable

### No fingerprint results

- host may be offline or not actively serving content
- the host may block HTTP requests or return generic responses
- some technologies may not be detected without recognizable markers

## Development notes

This repo is intentionally compact and readable. It aims to be easy to understand and extend, especially for security researchers and beginners studying ASM workflows.

If you want to extend it, the most natural places are:

- `core/fingerprint.py` for technology detection
- `core/risk.py` for scoring logic
- `core/exporter.py` for output formats
- `app.py` for the Streamlit dashboard experience

## License

This project is licensed under the MIT License. See `LICENSE` for details.

## Contact

- Author: Harsh Saini
- Brand: MR CYBER PULSE
- GitHub: https://github.com/mrcyberharsh
- Repository: https://github.com/mrcyberharsh/pulse-infragraph

---

<p align="center">
  <strong>pulse-infragraph</strong> · Community Edition · Built for authorized asset discovery
</p>
