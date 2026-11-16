# JASUSI — Product Requirements (Capstone Proposal Core)

## 1. Problem statement
Mobile-money and SMS fraud is one of the most common forms of cybercrime in Kenya. Scammers send fake
M-Pesa "reversal" requests, fake bank/KRA alerts, loan offers, job offers and phishing links. Generic
spam filters miss them because they are written in English, Swahili, Sheng or a mix of all three, and they
copy official message formats. Most users have no easy way to check a suspicious message before acting on it.

## 2. Aim
Build an explainable AI system that detects phishing and smishing in SMS, email and URLs, tuned for the
Kenyan context, and exposes it through a scalable API with user-facing clients.

## 3. Objectives
1. Build and label a Kenyan-context dataset of scam and legitimate messages (target ≥ 3,000 labelled samples).
2. Train and compare a classical baseline and a fine-tuned multilingual transformer for message classification.
3. Train a URL phishing classifier using lexical and host-based features.
4. Combine ML scores with threat-intelligence lookups into one explainable risk score.
5. Deploy as a containerised REST API with a web scanner, browser extension and analyst dashboard.
6. Evaluate detection performance, latency and usability with real users.

## 4. Research questions
- RQ1: How well does a fine-tuned multilingual transformer detect code-switched (English/Swahili/Sheng) smishing compared with a TF-IDF baseline?
- RQ2: Does adding threat intelligence and URL features improve detection over text-only models?
- RQ3: Do explanations increase user trust and correct decisions?

## 5. Users
| User | Need |
|---|---|
| Everyday mobile-money user | "Is this message a scam?" in seconds, in plain language |
| SME / SACCO staff | Check suspicious emails and links before clicking |
| Security analyst (B2B) | Dashboard of scan trends, top scam campaigns, IOCs |
| Developer / partner | REST API to plug detection into their own app |

## 6. MVP scope (must-have)
- [ ] `/scan/sms`, `/scan/email`, `/scan/url` endpoints with verdict, risk score and reasons
- [ ] Text classifier (baseline + transformer) and URL classifier
- [ ] IOC extraction (URLs, phone numbers, paybill/till numbers, emails)
- [ ] Threat-intel enrichment with caching and graceful failure
- [ ] Web "paste & scan" page
- [ ] Chrome extension: right-click a link or selected text → scan
- [ ] Analyst dashboard: scan volume, verdict split, top categories, recent IOCs
- [ ] User feedback loop ("Was this correct?")
- [ ] Docker deployment + CI

## 7. Stretch goals
- Android app that reads incoming SMS (with permission) and warns in real time
- WhatsApp / Telegram bot (forward a message → get a verdict)
- Scam campaign clustering (group similar scams to spot active campaigns)
- Active-learning retraining from user feedback
- Public API keys + usage tiers (the B2B path)

## 8. Out of scope (for the capstone)
- Live crawling or sandboxing of phishing pages
- Voice / call fraud detection
- Production-grade multi-tenant billing

## 9. Success metrics
| Metric | Target |
|---|---|
| Scam recall (SMS) | ≥ 0.92 |
| F1 (SMS, binary) | ≥ 0.90 |
| False-positive rate on legit | ≤ 5% |
| URL model ROC-AUC | ≥ 0.95 |
| p95 API latency (SMS, no intel) | < 300 ms |
| User test: correct decisions with explanation vs. without | measurable improvement (n ≥ 20 users) |

## 10. Ethics
- Informed consent for every donated message; anonymisation before storage; Kenya DPA 2019 compliance.
- Ethics approval from the university if user testing involves collecting personal data.
- Clearly communicate that JASUSI gives risk guidance, not a guarantee.
