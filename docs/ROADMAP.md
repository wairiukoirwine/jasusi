# JASUSI — Roadmap (assumes ~12 weeks, solo — adjust once confirmed)

Claude Code: work one milestone at a time and tick boxes as tasks finish.

## M0 — Setup (Week 1)
- [x] Repo, folder structure, `.gitignore`, `.env.example`, pre-commit (ruff, black)
- [x] `docker-compose.yml` with postgres, redis, mlflow
- [x] FastAPI skeleton with `/v1/health` + first test
- [x] GitHub Actions CI (lint + test)
- [ ] Proposal approved by supervisor

> M0 note: the compose file is syntax-checked only (not yet started against a Docker daemon).

## M1 — Data (Weeks 1–3)
- [ ] Consent form + donation form live — text drafted in `docs/CONSENT_FORM.md`; needs approval and publishing
- [x] `extract/anonymise.py` + tests (phones, names, IDs) — names are rule-based and will miss some
- [x] `docs/LABELLING_GUIDE.md`
- [ ] Collect + label Kenyan SMS (target in DATA_PLAN) — **not started; the biggest gap**
- [x] Download + clean public datasets — per-source breakdowns are in `docs/reports/`; no EDA notebook yet
- [x] Frozen train/val/test splits (`ml/configs/splits_v1.lock.json`)

## M2 — Text model (Weeks 3–5)
- [x] Baseline TF-IDF + LR, metrics logged to MLflow
- [ ] Fine-tune AfroXLMR / multilingual DistilBERT (Google Colab GPU) — script written, **never run**
- [ ] Compare models; error analysis on false negatives — leave-one-source-out done for the baseline only
- [ ] Export best model to ONNX — `detectors/text_detector.py` + tests are done, serving the baseline (joblib)

## M3 — URL model + IOC extraction (Weeks 5–6)
- [x] `ml/features/url_features.py` (shared) + tests
- [x] Train XGBoost URL model — SHAP values are in the report as a table (no plots)
- [x] `extract/iocs.py` (URLs, KE phones, paybill/till, emails) + tests
- [x] `detectors/url_detector.py`

## M4 — Threat intel + risk engine (Weeks 6–7)
- [x] VirusTotal, PhishTank, WHOIS (RDAP), Safe Browsing clients (async, cached, fail-open) — tested against mocks only
- [x] `engine/risk_engine.py` + `engine/explainer.py`
- [x] Full `/v1/scan/*` endpoints + `/v1/feedback`
- [x] API keys + rate limiting

## M5 — Clients (Weeks 7–9)
- [x] Web paste & scan page
- [ ] Chrome MV3 extension (context-menu scan for links + selected text) — written, **not yet loaded in Chrome**
- [x] Analyst dashboard (stats, trends, IOCs) — feedback shows as an agreement rate; no review screen yet

## M6 — Hardening + deploy (Weeks 9–10)
- [ ] Security review: OWASP API Top 10 checklist, `pip-audit`, input fuzzing — checklist (`docs/SECURITY.md`) and audits done; fuzzing not done
- [x] Load test: p95 latency report (`docs/reports/load_test.md`, own script instead of Locust) — misses the target at 20 concurrent clients
- [ ] Deploy demo environment — Dockerfile and compose written, never built

## M7 — Evaluation + write-up (Weeks 10–12)
- [ ] Final metrics on frozen test + Kenyan-only test — baseline and URL model reported; no usable Kenyan-only set
- [ ] User study (n ≥ 20): with vs without explanations
- [ ] Report chapters, demo video, defence slides

## Stretch
- [ ] Android SMS app · WhatsApp/Telegram bot · campaign clustering · active learning
