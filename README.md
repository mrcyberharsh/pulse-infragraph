# pulse-infragraph

<p align="center">
  <img src="logo.png" alt="pulse-infragraph logo" width="420" />
</p>

<p align="center"><strong>Community Edition · Open-source Attack Surface Management</strong></p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white" />
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green.svg" />
  <img alt="Platforms" src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-0ea5e9" />
  <img alt="Graph" src="https://img.shields.io/badge/Graph-Neo4j-4581C3?logo=neo4j&logoColor=white" />
</p>

**pulse-infragraph** helps security learners and authorized security teams build a clearer picture of a domain's public-facing assets. It combines passive subdomain discovery, HTTP technology fingerprinting, explainable risk signals, graph storage, and exportable reports.

> Use only with domains you own or have explicit permission to assess.

## Highlights

- Passive subdomain discovery using certificate-transparency data
- HTTP(S) technology fingerprinting
- Explainable heuristic risk scores with human-readable reasons
- Optional Neo4j graph persistence for domain, asset, and technology relationships
- Local scan snapshots (up to 100 runs) with per-domain asset and risk history
- New/removed asset comparison and risk-score trend chart
- Optional Neo4j timeline for first-seen asset records
- JSON, CSV, plain-text host-list, and PDF reports
- Streamlit dashboard and command-line workflow
- Windows, macOS, and Linux setup guidance

## Architecture at a glance

```text
Domain input
    |
    v
Discovery -> HTTP fingerprinting -> Risk analysis
    |                |                   |
    +----------------+-------------------+
                     |
              Asset records
                     |
          +----------+----------+
          |                     |
      Streamlit UI          Neo4j (optional)
          |
      JSON / CSV / TXT / PDF exports
```

## Requirements

- Python 3.11+
- Git
- Internet access for certificate-transparency lookups and HTTP checks
- Docker (optional, for the recommended Neo4j setup)

## Quick start

```bash
git clone https://github.com/mrcyberharsh/pulse-infragraph.git
cd pulse-infragraph
python -m venv .venv
```

Activate the environment:

**Linux / macOS**
```bash
source .venv/bin/activate
```

**Windows PowerShell**
```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies and launch:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Open the local Streamlit URL printed in the terminal and enter a domain you are authorized to assess.

## Optional: Neo4j

Start the repository's Neo4j service:

```bash
docker compose up -d neo4j
```

Configure the connection using environment variables. Neo4j remains disabled unless you explicitly provide `NEO4J_PASSWORD`; use a strong local secret.

**Linux / macOS**
```bash
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="replace-with-a-strong-password"
```

**Windows PowerShell**
```powershell
$env:NEO4J_URI="bolt://localhost:7687"
$env:NEO4J_USER="neo4j"
$env:NEO4J_PASSWORD="replace-with-a-strong-password"
```

## CLI

For a terminal-only run:

```bash
python cli.py example.com

# Run core unit tests
python -m unittest discover -s tests -v
```

Use only an authorized test domain. Check the command's help output for available options.

## Risk model

Risk scores are heuristic indicators, not proof that a host is vulnerable or safe. Current documented signals include:

- Hostname keywords such as `dev`, `test`, `staging`, `admin`, `beta`, `internal`, and `api-dev`
- WordPress technology detection
- Optional exposure signals when supplied by an authorized scanner

The dashboard groups scores into SAFE (0–29), EXPOSED (30–59), and CRITICAL (60–100). Always validate findings manually before making a security decision.

## Export formats

- `subdomains.txt` — discovered hostnames
- `pulse-infragraph-report.json` — structured report data
- `pulse-infragraph-assets.csv` — spreadsheet-friendly asset rows
- `pulse-infragraph-report.pdf` — printable asset inventory report

## Project layout

```text
pulse-infragraph/
├── app.py
├── cli.py
├── core/
│   ├── engine.py
│   ├── exporter.py
│   ├── fingerprint.py
│   ├── graph.py
│   ├── history.py
│   ├── fingerprint.py
│   └── risk.py
├── tests/
│   └── test_core.py
├── logo.png
├── requirements.txt
├── docker-compose.yml
├── Dockerfile
├── install.sh
├── LICENSE
└── README.md
```

## Troubleshooting

| Issue | What to check |
|---|---|
| Neo4j is unavailable | Check Docker status and the configured connection variables |
| No subdomains appear | Certificate-transparency data may be incomplete or delayed |
| No fingerprint is detected | The host may be offline, block requests, or expose no recognizable markers |
| Dependency installation fails | Confirm Python 3.11+ and activate the virtual environment |

## Responsible use

- Assess only assets you own or are explicitly authorized to test.
- Respect service terms, rate limits, and upstream infrastructure.
- Treat automated results as leads that require human validation.
- Do not use the tool to access, disrupt, or test systems without permission.

## Contributing

Issues and pull requests are welcome. Please include reproducible steps, expected behavior, actual behavior, and relevant sanitized logs. Avoid sharing secrets, personal data, or sensitive target information in public issues.

## License and credits

Released under the [MIT License](LICENSE).

**pulse-infragraph v1.0.0 | Created by Harsh Saini (MR CYBER PULSE) | Open-Source ASM Tool**

- GitHub: https://github.com/mrcyberharsh
- Project: https://github.com/mrcyberharsh/pulse-infragraph
