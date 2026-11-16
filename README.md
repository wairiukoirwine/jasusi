# 🕵🏾 JASUSI

**AI-powered phishing & smishing shield for Kenya.**
Paste an SMS, email or link and get a verdict, a 0–100 risk score and plain-language reasons.

> Final-year AI + Cybersecurity capstone — Africa International University.
> JASUSI gives risk guidance, not a guarantee. When in doubt, contact your bank or Safaricom directly.

## What works today
- `POST /v1/scan/sms`, `/v1/scan/email`, `/v1/scan/url`, `POST /v1/feedback`, `GET /v1/stats/summary`, `GET /v1/health`
- Text model (TF-IDF + Logistic Regression) and URL model (XGBoost on lexical features), each with a
  rule-based fallback so the API runs even before you train anything
- IOC extraction (links, Kenyan phone numbers, paybill/till numbers, emails) and an anonymiser
- Risk engine with config-driven weights and thresholds; every verdict comes with reasons
- Threat-intel clients (VirusTotal, Google Safe Browsing, PhishTank, domain age): async, cached, fail-open
- Web app: "check a message" page and analyst dashboard; Chrome extension (right-click to check)
- API keys, rate limiting, input size limits; no message text is stored

**Read before quoting results:** [text model report](docs/reports/text_baseline.md),
[URL model report](docs/reports/url_model.md), [load test](docs/reports/load_test.md),
[security review](docs/SECURITY.md) and the "Known limits" section below.

## Run it (no Docker needed)
```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements-dev.txt
cp .env.example .env
(cd dashboard && npm ci && npm run build)      # builds the web app the API serves at /
uvicorn app.main:app --app-dir backend --reload
```
Open http://localhost:8000 for the web app and http://localhost:8000/docs for the API.
Without trained models the page shows a "Basic mode" notice and uses keyword rules.

```bash
curl -s localhost:8000/v1/scan/sms -H 'Content-Type: application/json' \
  -d '{"text":"Nimekutumia Ksh 3,500 kimakosa. Tafadhali rudisha haraka kwa 0712345678"}'
```

### Train the models (about 2 minutes on a laptop)
Unzip the public data pack so that `data/processed/sms_v0.csv` and `urls_v0.csv` exist
(`data/` is gitignored — never commit it), then:
```bash
pip install -r ml/requirements.txt
python -m ml.training.make_splits          # only once: the test set is frozen afterwards
python -m ml.training.synth_kenyan_legit   # synthetic Kenyan legit messages (training only)
python -m ml.training.train_text
python -m ml.training.train_url
python -m ml.training.evaluate             # rewrites docs/reports/*.md
mlflow ui --backend-store-uri sqlite:///mlflow.db
```
Restart the API; `/v1/health` then reports `text-tfidf-lr-v2` and `url-xgb-v1`.

### Demo data for the dashboard
```bash
DATABASE_URL=sqlite:///./demo.db python scripts/seed_demo.py
DATABASE_URL=sqlite:///./demo.db uvicorn app.main:app --app-dir backend
```
These are invented volumes for demonstrations. Never present them as usage figures.

### With Postgres, Redis and MLflow
```bash
docker compose up -d                              # services only
docker compose --profile app up -d --build        # services + API/web app on :8000
```
Set `DATABASE_URL` and `REDIS_URL` in `.env` as shown in `.env.example` when running the API outside Docker.

### Other commands
```bash
ruff check . && black --check . && pytest -q      # backend checks
(cd dashboard && npm run dev)                     # web app with hot reload on :5173
python -m app.core.security create --owner "Demo SACCO"   # run from backend/: create an API key
python scripts/loadtest.py --help
```
Chrome extension: see [extension/README.md](extension/README.md).

## Known limits
- **No real Kenyan data yet.** Training uses public datasets (Tanzanian Swahili, UK/Singapore English,
  international smishing) plus 1,200 *synthetic* Kenyan legit messages. The false-positive rate on real
  M-Pesa, bank and OTP messages has not been measured, and the Kenyan-only test set has 3 rows.
- **Scores drop sharply on unseen sources.** In-distribution test F1 is 0.986, but when a whole source is
  held out, recall falls to 0.35 (IMC'25) and the false-positive rate rises to 0.96 (UCI English).
- **Scam categories come from keyword rules**, not from the model (the public data has no such labels).
- **The URL model has a ~10% false-positive rate** at the default threshold. A short allowlist of
  official sites and Kenyan institutional domains (`.go.ke`, `.ac.ke`, `.sc.ke`) covers the worst cases.
- **Email uses the SMS text model**; there is no email-specific training data.
- **Threat-intel clients are tested against mocks only**, never against the live services.
- **Not done:** transformer fine-tuning (script provided, never run), ONNX export, Alembic migrations,
  deployment, user study, real data collection.
- Compose and the Dockerfile are syntax-checked but have not been built or started.

## Docs
[Product requirements](docs/PRD.md) · [Architecture](docs/ARCHITECTURE.md) · [Data plan](docs/DATA_PLAN.md) ·
[Roadmap](docs/ROADMAP.md) · [Setup checklist](docs/SETUP.md) · [Labelling guide](docs/LABELLING_GUIDE.md) ·
[Consent form draft](docs/CONSENT_FORM.md) · [Security review](docs/SECURITY.md)
