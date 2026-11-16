# 🕵🏾 JASUSI

**AI-powered phishing & smishing shield for Kenya.**
Paste an SMS, email or link and get a verdict, a 0–100 risk score and plain-language reasons.

> Final-year AI + Cybersecurity capstone — Africa International University.

## Features (MVP)
- Detects M-Pesa reversal scams, fake bank/KRA alerts, loan and job scams, phishing links
- Understands English, Swahili and Sheng
- Explainable verdicts (why it was flagged)
- Threat-intel enrichment (VirusTotal, PhishTank, WHOIS, Safe Browsing)
- REST API · Web scanner · Chrome extension · Analyst dashboard

## Quick start
```bash
cp .env.example .env                          # add your API keys
docker compose up -d                          # postgres, redis, mlflow
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements-dev.txt
pre-commit install                            # ruff + black on every commit
cd backend && uvicorn app.main:app --reload   # http://localhost:8000/v1/health
```

## Checks (run from the repo root)
```bash
ruff check . && black --check .
pytest -q
```

## Docs
- [Product requirements](docs/PRD.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Data plan](docs/DATA_PLAN.md)
- [Roadmap](docs/ROADMAP.md)
- [Setup checklist](docs/SETUP.md)

## Disclaimer
JASUSI provides risk guidance, not a guarantee. When in doubt, contact your bank or Safaricom directly via official channels.
