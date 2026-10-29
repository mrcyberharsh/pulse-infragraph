<div align="center">

<img src="logo.png" alt="pulse-infragraph logo" width="620">

# pulse-infragraph
### Community Edition v1.5.0 · Open-Source Attack Surface Management
**Created by Harsh Saini — MR CYBER PULSE**

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platforms](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)

*Discover public assets, understand technology exposure, prioritize review, and export findings.*

</div>

## Contents
- [Overview](#overview) · [Features](#features) · [Installation](#installation) · [Configuration](#configuration)
- [Usage](#how-to-use) · [Risk scoring](#risk-scoring) · [Exports](#exports) · [Troubleshooting](#troubleshooting)
- [Author/contact](#author-and-contact) · [Responsible use](#responsible-use) · [License](#license)

## Overview
`pulse-infragraph` is a beginner-friendly open-source Attack Surface Management (ASM) and OSINT graph project for bug bounty hunters and security researchers. It combines passive certificate-transparency discovery, async HTTP fingerprinting, explainable heuristic risk scoring, Neo4j relationships, and exports in a dark cyber-themed Streamlit dashboard.

> **Authorization required:** Use only on domains you own or have explicit permission to assess. Results can be incomplete. Fingerprints and scores are not proof of vulnerabilities.

## Features
- **Risk Pulse Engine:** explainable 0–100 scores, levels, colors, and reasons.
- **Technology fingerprinting:** checks response headers/body for Cloudflare, WordPress, AWS, Nginx, and React.
- **Neo4j graph:** domain, subdomain, and technology relationships.
- **Timeline:** assets first observed during the previous 24 hours.
- **Attack-path graph:** risk-colored nodes/edges and score-scaled sizes.
- **Exports:** Nuclei target list, JSON report with author credit, and CSV.
- **Graceful DB handling:** dashboard warns if Neo4j is offline.
- **Cross-platform:** Windows, macOS, and Linux with Python 3.11+.

## Requirements
- Python 3.11+, Git, Docker Engine/Desktop (recommended for Neo4j)
- Internet access for certificate-transparency lookup and HTTP fingerprinting

## Installation

### Linux
```bash
git clone https://github.com/mrcyberharsh/pulse-infragraph.git
cd pulse-infragraph
chmod +x install.sh
./install.sh
docker compose up -d neo4j
pulse-infragraph
```
The installer creates a virtual environment, installs requirements, and adds a launcher under `/usr/local/bin` (may require `sudo`). It does not install Docker itself.

Manual launch:
```bash
source .venv/bin/activate
streamlit run app.py
```

### Windows PowerShell
```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
docker compose up -d neo4j
streamlit run app.py
```

### macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
docker compose up -d neo4j
streamlit run app.py
```

### Docker Compose
```bash
docker compose up --build
```
Open `http://localhost:8501`. Change the sample Neo4j password before using beyond local development.

## Configuration
Set credentials to match Neo4j. Never commit real secrets.

Linux/macOS:
```bash
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="replace-with-a-strong-password"
```
Windows PowerShell:
```powershell
$env:NEO4J_URI="bolt://localhost:7687"
$env:NEO4J_USER="neo4j"
$env:NEO4J_PASSWORD="replace-with-a-strong-password"
```

## How to use
1. Start Neo4j for saved graph data and timeline history.
2. Launch Streamlit and enter an authorized root domain such as `example.com` (domain only; no URL or wildcard).
3. Click **Discover & Analyze**.
4. Review asset counts, risk, technologies, and graph.
5. Expand **Risk Details** for EXPOSED/CRITICAL heuristic signals.
6. Download Nuclei target list, JSON, or CSV.

Certificate-transparency discovery is passive. Fingerprinting sends HTTP(S) requests to discovered hosts. Results depend on upstream services, DNS, network access, and target responses.

## Risk scoring
| Signal | Points | Notes |
|---|---:|---|
| Hostname includes `dev`, `test`, `staging`, `admin`, `beta`, `internal`, or `api-dev` | +40 | Broad heuristic |
| WordPress detected | +20 | Review versions, plugins, hardening |
| Open ports supplied by a future/authorized scanner integration | +5 each, max +20 | Placeholder; this app does not scan ports |

- 🟢 **SAFE:** 0–29
- 🟡 **EXPOSED:** 30–59
- 🔴 **CRITICAL:** 60–100

Scores prioritize review; SAFE does not guarantee security.

## Exports
- `subdomains.txt`: one hostname per line for a Nuclei target list. This app does **not** execute Nuclei.
- `pulse-infragraph-report.json`: domain, findings, risk, technologies, timestamp, and tool credit.
- `pulse-infragraph-assets.csv`: spreadsheet-friendly risk and technology data.

## Project structure
```text
pulse-infragraph/
├── app.py
├── core/{engine.py,graph.py,risk.py,fingerprint.py,exporter.py}
├── logo.png
├── requirements.txt
├── install.sh
├── Dockerfile
├── docker-compose.yml
├── README.md
└── LICENSE
```

## Troubleshooting
**Neo4j offline:** run `docker ps`, then `docker compose up -d neo4j`; inspect `docker compose logs neo4j`. Check environment variables.

**No subdomains:** certificate-transparency records may be missing or the service may be unavailable. Verify the domain and retry later.

**No fingerprint results:** hosts may be offline, block requests, or return no recognizable markers.

**Streamlit missing:** activate `.venv` and run `pip install -r requirements.txt`.

## Author and contact
- **Author:** Harsh Saini
- **Brand:** MR CYBER PULSE
- **GitHub:** [@mrcyberharsh](https://github.com/mrcyberharsh)
- **Repository:** [pulse-infragraph](https://github.com/mrcyberharsh/pulse-infragraph)
- **Email:** `manager.prachi@zohomail.in` — replace with your public project email
- **Bug reports:** [GitHub Issues](https://github.com/mrcyberharsh/pulse-infragraph/issues)

Replace placeholders before publishing; only share contact details you want public.

## Responsible use
For education and authorized security work only. Obtain permission, follow program scope and rate limits, and comply with applicable laws. Do not test systems without authorization.

## License
MIT License. Include the repository's `LICENSE` file before publishing.

---
<div align="center">
**pulse-infragraph v1.0.0 | Created by Harsh Saini (MR CYBER PULSE) | Open-Source ASM Tool**
</div>
