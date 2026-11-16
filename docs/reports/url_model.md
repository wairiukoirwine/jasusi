# URL model — test-set report

Model `url-xgb-v1` (XGBoost on 26 lexical features, 525 trees).
Generated 2026-11-16T08:13:16+00:00 by `python -m ml.training.evaluate`.
Positive class = malicious. Threshold 0.5. Split by registered domain, test set frozen.

## Headline (frozen test set)
| Slice | n | Recall | Precision | F1 | FPR | ROC-AUC | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|---|
| All test URLs | 66676 | 0.8683 | 0.7739 | 0.8184 | 0.0992 | 0.9547 | 16268 | 4754 | 2468 | 43186 |

## Recall at fixed false-positive rates
| Target FPR | Threshold | Recall |
|---|---|---|
| 1% | 0.901 | 0.6439 |
| 5% | 0.661 | 0.8044 |
| 10% | 0.498 | 0.8689 |

## By source
| Slice | n | Recall | Precision | F1 | FPR | ROC-AUC | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|---|
| jpcert_phishurl | 13436 | 0.9133 | 1.0000 | 0.9547 | n/a | n/a | 12271 | 0 | 1165 | 0 |
| savan77_malicious_url | 53240 | 0.7542 | 0.4567 | 0.5689 | 0.0992 | 0.9121 | 3997 | 4754 | 1303 | 43186 |

## JPCERT phishing recall by year reported
| Slice | n | Recall | Precision | F1 | FPR | ROC-AUC | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|---|
| 2019 | 349 | 0.8338 | 1.0000 | 0.9094 | n/a | n/a | 291 | 0 | 58 | 0 |
| 2020 | 636 | 0.9214 | 1.0000 | 0.9591 | n/a | n/a | 586 | 0 | 50 | 0 |
| 2021 | 1201 | 0.9500 | 1.0000 | 0.9744 | n/a | n/a | 1141 | 0 | 60 | 0 |
| 2022 | 2814 | 0.9623 | 1.0000 | 0.9808 | n/a | n/a | 2708 | 0 | 106 | 0 |
| 2023 | 2636 | 0.8942 | 1.0000 | 0.9441 | n/a | n/a | 2357 | 0 | 279 | 0 |
| 2024 | 2331 | 0.8850 | 1.0000 | 0.9390 | n/a | n/a | 2063 | 0 | 268 | 0 |
| 2025 | 2206 | 0.9347 | 1.0000 | 0.9663 | n/a | n/a | 2062 | 0 | 144 | 0 |
| 2026 | 1263 | 0.8416 | 1.0000 | 0.9140 | n/a | n/a | 1063 | 0 | 200 | 0 |

## Most influential features (mean |SHAP| on 5,000 test URLs)
| Feature | mean abs SHAP |
|---|---|
| `path_len` | 1.063 |
| `tld_len` | 0.586 |
| `n_slashes` | 0.458 |
| `tld_suspicious` | 0.454 |
| `entropy_path` | 0.409 |
| `n_special` | 0.354 |
| `entropy_host` | 0.325 |
| `n_suspicious_words` | 0.274 |
| `n_digits` | 0.271 |
| `n_subdomains` | 0.235 |

## Top features by gain
| Feature | gain |
|---|---|
| `tld_suspicious` | 1298.2 |
| `n_suspicious_words` | 498.5 |
| `tld_len` | 434.0 |
| `path_len` | 260.0 |
| `n_subdomains` | 183.4 |
| `has_ip` | 142.9 |
| `brand_mismatch` | 115.2 |
| `n_digits` | 113.8 |
| `n_hyphens_host` | 112.8 |
| `is_shortener` | 104.5 |

## Reading these numbers
- Legit URLs come from one 2017-era list and phishing URLs mostly from JPCERT (Japan-heavy brands), so part of the separation is source style. Fresh legit domains (e.g. Tranco) and Kenyan phishing URLs are needed before trusting this in the field.
- Lexical features cannot see page content; a clean-looking URL on a compromised site will pass. Threat intelligence covers part of that gap.
