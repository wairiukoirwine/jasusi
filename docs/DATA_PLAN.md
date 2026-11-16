# JASUSI — Data Plan

## Sources
| Source | Type | Use |
|---|---|---|
| Own collection: donated scam SMS from friends, family, classmates, WhatsApp groups | Kenyan smishing (key contribution) | Train + test |
| Own collection: donated legit SMS (M-Pesa confirmations, bank alerts, OTPs, personal chats) | Kenyan legit | Train + test (hard negatives!) |
| Public screenshots of scam messages shared on X/Facebook by Safaricom, banks, DCI, news outlets | Kenyan smishing | Train (transcribe text only) |
| UCI SMS Spam Collection | General spam/ham | Pre-training / augmentation |
| Mendeley "SMS Phishing Dataset" (smishing) | General smishing | Augmentation |
| Phishing email corpora (e.g. Nazario, Enron ham) | Emails | Email channel |
| PhishTank / OpenPhish (phishing URLs) + Tranco top sites (legit URLs) | URLs | URL model |

> Check each public dataset's licence before use and cite it in the report.

## Collection protocol
1. Google Form: "Donate a scam message" — paste text, sender ID type (number/shortcode), date received, consent checkbox.
2. Explain clearly what the data is used for, that it is anonymised, and that donors can withdraw.
3. Anonymise **before** saving to `data/raw/`: phone numbers → `<PHONE>`, names → `<NAME>`, ID numbers → `<ID>`, amounts kept.
4. Never store donor identity alongside messages.

## Labelling
- Labels: see categories in `CLAUDE.md`.
- Tool: Label Studio (local) or a simple spreadsheet.
- Double-label at least 20% of samples (ask a classmate) and report Cohen's kappa.
- Labelling guide with 2–3 examples per category lives in `docs/LABELLING_GUIDE.md` (create in Milestone 1).

## Targets
| Set | Target size |
|---|---|
| Kenyan scam SMS | ≥ 1,000 |
| Kenyan legit SMS (incl. real M-Pesa/bank formats) | ≥ 1,500 |
| Augmentation (public) | as needed |
| URLs | ≥ 20,000 (balanced) |

## Splits
- Stratified 70 / 15 / 15, seed 42. Test set frozen and stored as `data/processed/test_v1.csv`.
- Extra **Kenyan-only test set** reported separately, so public data doesn't inflate results.
- Watch for near-duplicates across splits (same scam template). Deduplicate with MinHash or fuzzy matching.

## Augmentation (if data is thin)
- Template variation (swap amounts, names, numbers)
- Back-translation English ↔ Swahili
- LLM-generated synthetic scams, clearly flagged as synthetic and **never** used in the test set
