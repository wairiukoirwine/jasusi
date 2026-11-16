# CLAUDE.md — JASUSI

> Claude Code reads this file first in every session. Keep it current.

## What JASUSI is
JASUSI (Swahili: "spy") is an AI-powered phishing and smishing shield for Kenya.
It scans **SMS, emails and URLs** and returns a **verdict + risk score (0–100) + explanation**
for scams such as fake M-Pesa reversals, fake KRA/bank alerts, loan scams and fake job offers.

It is a final-year **AI + Cybersecurity capstone** (BSc Data Analytics & AI, Africa International University),
designed to scale into a real product (consumer app → browser extension → B2B API for banks, SACCOs, telcos).

Full spec: `docs/PRD.md` · Architecture: `docs/ARCHITECTURE.md` · Data: `docs/DATA_PLAN.md` · Plan: `docs/ROADMAP.md`

## Tech stack (do not change without asking)
| Layer | Choice |
|---|---|
| Language | Python 3.11 (backend + ML), TypeScript (dashboard + extension) |
| API | FastAPI + Pydantic v2 + Uvicorn |
| Text model | Baseline: TF-IDF + Logistic Regression → Main: fine-tuned `Davlan/afro-xlmr-base` or `distilbert-base-multilingual-cased` (Hugging Face Transformers) |
| URL model | Lexical + host features → XGBoost |
| Explainability | SHAP (URL model), token attributions / LIME (text model) |
| Threat intel | VirusTotal API, PhishTank / OpenPhish feeds, WHOIS domain age, Google Safe Browsing |
| DB | PostgreSQL (SQLAlchemy 2 + Alembic). SQLite allowed for local dev only |
| Cache / queue | Redis (cache threat-intel lookups, rate limiting) |
| Dashboard | React + Vite + TypeScript + Tailwind |
| Client (MVP) | Web "paste & scan" page + Chrome extension (Manifest V3). Android app is a stretch goal |
| Infra | Docker + docker-compose. GitHub Actions CI |
| Experiment tracking | MLflow (local) |
| Testing | pytest, httpx; Vitest for frontend |

## Repo layout
```
jasusi/
├── CLAUDE.md
├── README.md
├── docs/                 # PRD, architecture, data plan, roadmap, setup
├── backend/
│   └── app/
│       ├── main.py       # FastAPI entrypoint
│       ├── api/          # routers: /scan/sms, /scan/email, /scan/url, /feedback, /health
│       ├── core/         # config, security, logging
│       ├── detectors/    # text_detector.py, url_detector.py, threat_intel.py
│       ├── engine/       # risk_engine.py (combines scores), explainer.py
│       ├── extract/      # IOC extraction: URLs, phone numbers, paybill/till numbers, emails
│       ├── db/           # models, session, migrations
│       └── schemas/      # Pydantic request/response models
│   └── tests/
├── ml/
│   ├── notebooks/        # EDA only — no production logic here
│   ├── training/         # train_text.py, train_url.py, evaluate.py
│   ├── features/         # url_features.py (shared with backend)
│   └── models/           # saved artifacts (gitignored, versioned via MLflow)
├── data/                 # raw/ interim/ processed/ — ALL gitignored
├── dashboard/            # React analyst dashboard
├── extension/            # Chrome MV3 extension
├── docker-compose.yml
└── .github/workflows/
```

## Architecture rules
- Start as a **modular monolith** (one FastAPI service, strictly separated modules). Each detector must be
  callable on its own through a clean interface so it can later be split into its own service.
- Every detector implements: `predict(input) -> DetectorResult(score: float 0..1, label: str, evidence: list, latency_ms)`.
- The **risk engine** combines detector results with weighted rules into a final `risk_score` 0–100 and
  verdict: `SAFE` (<30) · `SUSPICIOUS` (30–69) · `SCAM` (≥70). Thresholds live in config, not code.
- Every response must include a human-readable `reasons[]` list. No unexplained verdicts.
- Threat-intel calls are async, cached in Redis (TTL 24h) and must **fail open gracefully**: if an
  external API is down, still return the ML verdict and flag `intel_unavailable: true`.
- Feature extraction code for the URL model lives in `ml/features/` and is imported by the backend.
  Training and inference MUST use the same function.

## API contract (v1)
`POST /v1/scan/sms` · `POST /v1/scan/email` · `POST /v1/scan/url` · `POST /v1/feedback` · `GET /v1/health`

Response shape:
```json
{
  "scan_id": "uuid",
  "verdict": "SCAM",
  "risk_score": 87,
  "category": "mpesa_reversal_scam",
  "reasons": ["Asks you to reverse a payment", "Sender is not an official M-Pesa shortcode", "Contains urgency language"],
  "iocs": {"urls": [], "phones": ["0712xxxxxx"], "paybills": [], "emails": []},
  "detectors": {"text": 0.94, "url": null, "intel": null},
  "model_version": "text-v0.3",
  "latency_ms": 142
}
```

## Scam categories (labels)
`legit` · `mpesa_reversal_scam` · `fake_bank_or_kra` · `loan_scam` · `job_scam` · `prize_or_promo_scam` ·
`phishing_link` · `impersonation` · `other_scam`. (Binary `scam/legit` is used for the headline metric.)

## Security & privacy (non-negotiable)
- **Kenya Data Protection Act 2019** applies. Collect SMS data only with consent; anonymise phone numbers,
  names and ID numbers before anything is stored or used for training (`extract/anonymise.py`).
- Never commit real messages, API keys or `.env`. Use `.env.example` for placeholders.
- Scanned content is stored hashed by default; raw text is kept only if the user opts in via `/feedback`.
- Never visit or fetch a suspicious URL directly from the backend. Use lexical features + reputation APIs only
  (no live crawling of phishing pages in MVP).
- Rate-limit every public endpoint (Redis). Validate and size-limit all input (SMS ≤ 2,000 chars, email ≤ 50 KB).
- Follow OWASP API Security Top 10. Dependency scanning in CI (`pip-audit`, `npm audit`).

## ML rules
- Always build the **baseline first** (TF-IDF + LR) and record its metrics before any transformer work.
- Stratified train/val/test split, fixed seed `42`. The test set is frozen once created. Never tune on it.
- Headline metrics: **Recall on SCAM** (missing a scam is the costly error), F1, Precision, ROC-AUC, and
  false-positive rate on legit messages. Report a confusion matrix per category.
- Log every training run to MLflow (params, metrics, artifacts).
- Models must run on CPU with p95 inference < 300 ms for SMS.

## Coding conventions
- Python: type hints everywhere, `ruff` + `black`, docstrings on public functions.
- Small focused PRs/commits. Conventional commits (`feat:`, `fix:`, `ml:`, `docs:`, `test:`).
- Every new endpoint or detector ships with tests. Keep coverage ≥ 70% on `backend/app`.
- No secrets, no real user data, no large model files in git.

## How to work with me (Claude Code)
1. Before coding a feature, read the matching section of `docs/` and confirm the plan in 3–5 bullets.
2. Work milestone by milestone from `docs/ROADMAP.md`. Don't jump ahead.
3. After each task: run tests, update `docs/ROADMAP.md` checkboxes and note anything that changed.
4. Ask before adding new dependencies, changing the stack, or touching data privacy logic.
5. Keep explanations short. Show what changed and how to run it.

## Common commands
```bash
docker compose up -d                              # postgres + redis + mlflow (optional for local dev)
uvicorn app.main:app --app-dir backend --reload   # run from the repo root
ruff check . && black --check . && pytest -q
python -m ml.training.train_text --config ml/configs/text_baseline.yaml
python -m ml.training.evaluate                    # rewrites docs/reports/*.md from a real run
mlflow ui --backend-store-uri sqlite:///mlflow.db
cd dashboard && npm run dev
```

## Current state (keep this honest)
- Serving model is the TF-IDF + LR baseline (joblib), not a transformer; categories come from keyword rules.
- Local dev defaults to SQLite and an in-memory cache; Postgres/Redis are opt-in via `.env`.
- Tables are created at startup; add Alembic with the first schema change that needs a migration.
- Never quote a metric that is not in `docs/reports/` from a real run. Never tune on the frozen test set.
