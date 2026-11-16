# JASUSI — Architecture

## High-level flow
```
 Clients                         Backend (FastAPI, modular monolith)                    Storage
┌──────────────┐               ┌──────────────────────────────────────────────┐       ┌──────────┐
│ Web scanner  │──┐            │  API gateway  (auth · rate limit · validate)  │       │ Postgres │
│ Chrome ext.  │──┼── HTTPS ──▶│        │                                      │──────▶│ scans,   │
│ Android*     │──┤            │        ▼                                      │       │ feedback │
│ Partner API  │──┘            │  IOC extractor + anonymiser                   │       └──────────┘
└──────────────┘               │        │                                      │       ┌──────────┐
                               │   ┌────┼──────────────┬──────────────┐       │       │  Redis   │
                               │   ▼    ▼              ▼              │       │◀─────▶│ cache,   │
                               │ Text detector   URL detector   Threat intel  │       │ ratelimit│
                               │ (transformer)   (XGBoost)      (VT, PhishTank│       └──────────┘
                               │   │                │            WHOIS, GSB)  │
                               │   └──────┬─────────┴──────────────┘          │       ┌──────────┐
                               │          ▼                                   │       │  MLflow  │
                               │   Risk engine → Explainer → Response         │       │ models   │
                               └──────────────────────────────────────────────┘       └──────────┘
                                                   │
                                                   ▼
                                        Analyst dashboard (React)
```
*Android = stretch goal

## Components
| Component | Responsibility | Scaling path |
|---|---|---|
| Gateway | Auth (API keys), rate limiting, input validation, request IDs | Put behind Nginx / cloud load balancer |
| IOC extractor | Regex + rules for URLs, KE phone numbers (`07xx`, `01xx`, `+254`), paybill/till, emails | Pure function, no state |
| Anonymiser | Masks phone numbers, names, ID numbers before storage | Pure function |
| Text detector | Classifies message text into scam categories | Separate inference service (TorchServe / ONNX Runtime) with autoscaling |
| URL detector | Lexical features (length, entropy, digits, subdomains, TLD, typosquats of `safaricom`, `kcb`, `equity`, `kra`…) + host features | Separate service |
| Threat intel | Async lookups, cached 24h, fail-open | Background workers (Celery/RQ) |
| Risk engine | Weighted combination + rule overrides (e.g. known-bad URL → force SCAM) | Config-driven |
| Explainer | Turns model evidence + rules into plain-English (and later Swahili) reasons | — |
| Dashboard | Stats, trends, IOC tables, feedback review | Static hosting |

## Risk engine (v1 logic)
```
base = 0.6 * text_score + 0.3 * url_score + 0.1 * intel_score   (weights renormalised if a part is missing)
overrides:
  - intel says malicious           → risk = max(risk, 90)
  - sender is verified shortcode   → risk = min(risk, 20)   (e.g. official M-Pesa sender)
  - urgency + money-request rules  → +10
risk_score = round(base * 100)
```
Weights and thresholds live in `backend/app/core/config.py` and are tuned on the validation set.

## Database (initial tables)
- `scans(id, channel, content_hash, risk_score, verdict, category, model_version, created_at, latency_ms)`
- `scan_iocs(scan_id, type, value_masked)`
- `feedback(scan_id, user_label, comment, consent_raw_text, raw_text_encrypted, created_at)`
- `api_keys(id, owner, hashed_key, tier, created_at, revoked)`

## Why a modular monolith first
One service is faster to build and debug in one semester. Each detector sits behind a strict interface,
so it can be lifted into its own container later without rewriting callers. That migration path
is a key part of the "scalable" argument in the report.

## Deployment
- Local: `docker compose` (api, postgres, redis, mlflow)
- Demo: Render / Railway / a small VPS. Models exported to ONNX for fast CPU inference
- CI: GitHub Actions: lint → tests → `pip-audit` → build image
