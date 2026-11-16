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
- [ ] Consent form + donation form live
- [ ] `extract/anonymise.py` + tests (phones, names, IDs)
- [ ] `docs/LABELLING_GUIDE.md`
- [ ] Collect + label Kenyan SMS (target in DATA_PLAN)
- [ ] Download + clean public datasets; EDA notebook
- [ ] Frozen train/val/test splits

## M2 — Text model (Weeks 3–5)
- [ ] Baseline TF-IDF + LR, metrics logged to MLflow
- [ ] Fine-tune AfroXLMR / multilingual DistilBERT (Google Colab GPU)
- [ ] Compare models; error analysis on false negatives
- [ ] Export best model to ONNX; `detectors/text_detector.py` + tests

## M3 — URL model + IOC extraction (Weeks 5–6)
- [ ] `ml/features/url_features.py` (shared) + tests
- [ ] Train XGBoost URL model + SHAP plots
- [ ] `extract/iocs.py` (URLs, KE phones, paybill/till, emails) + tests
- [ ] `detectors/url_detector.py`

## M4 — Threat intel + risk engine (Weeks 6–7)
- [ ] VirusTotal, PhishTank, WHOIS, Safe Browsing clients (async, cached, fail-open)
- [ ] `engine/risk_engine.py` + `engine/explainer.py`
- [ ] Full `/v1/scan/*` endpoints + `/v1/feedback`
- [ ] API keys + rate limiting

## M5 — Clients (Weeks 7–9)
- [ ] Web paste & scan page
- [ ] Chrome MV3 extension (context-menu scan for links + selected text)
- [ ] Analyst dashboard (stats, trends, IOCs, feedback review)

## M6 — Hardening + deploy (Weeks 9–10)
- [ ] Security review: OWASP API Top 10 checklist, `pip-audit`, input fuzzing
- [ ] Load test (Locust): p95 latency report
- [ ] Deploy demo environment

## M7 — Evaluation + write-up (Weeks 10–12)
- [ ] Final metrics on frozen test + Kenyan-only test
- [ ] User study (n ≥ 20): with vs without explanations
- [ ] Report chapters, demo video, defence slides

## Stretch
- [ ] Android SMS app · WhatsApp/Telegram bot · campaign clustering · active learning
