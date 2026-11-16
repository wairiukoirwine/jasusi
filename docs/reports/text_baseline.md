# Text baseline — test-set report

Model `text-tfidf-lr-v2` (TF-IDF word+char n-grams, Logistic Regression, C=8.0), trained 2026-11-16T08:12:29+00:00 on 15148 messages (1200 of them synthetic Kenyan legit messages, training only).
Generated 2026-11-16T08:12:36+00:00 by `python -m ml.training.evaluate`.
Positive class = scam or spam. Threshold 0.5. Test set is frozen (`ml/configs/splits_v1.lock.json`).

## Headline (frozen test set)
| Slice | n | Recall | Precision | F1 | FPR | ROC-AUC | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|---|
| All test messages | 2976 | 0.9777 | 0.9942 | 0.9859 | 0.0082 | 0.9978 | 1713 | 10 | 39 | 1214 |

Single-message CPU latency: p50 1.8 ms, p95 2.7 ms (target p95 < 300 ms).

## By original label
Recall is the meaningful column for `scam` and `spam`; FPR for `legit`.
| Slice | n | Recall | Precision | F1 | FPR | ROC-AUC | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|---|
| legit | 1224 | n/a | 0.0000 | n/a | 0.0082 | n/a | 0 | 10 | 0 | 1214 |
| scam | 1358 | 0.9816 | 1.0000 | 0.9907 | n/a | n/a | 1333 | 0 | 25 | 0 |
| spam | 394 | 0.9645 | 1.0000 | 0.9819 | n/a | n/a | 380 | 0 | 14 | 0 |

## By source
| Slice | n | Recall | Precision | F1 | FPR | ROC-AUC | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|---|
| afriscam | 9 | 1.0000 | 0.8889 | 0.9412 | 1.0000 | 0.8750 | 8 | 1 | 0 | 0 |
| bongoscam | 156 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 82 | 0 | 0 | 74 |
| imc25_smishing | 1350 | 0.9785 | 1.0000 | 0.9891 | n/a | n/a | 1321 | 0 | 29 | 0 |
| ssd_swahili | 697 | 0.9910 | 0.9821 | 0.9865 | 0.0084 | 0.9980 | 220 | 4 | 2 | 471 |
| uci_sms_spam | 764 | 0.9111 | 0.9425 | 0.9266 | 0.0074 | 0.9903 | 82 | 5 | 8 | 669 |

## By language group
| Slice | n | Recall | Precision | F1 | FPR | ROC-AUC | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|---|
| EN/SW/Sheng mix (AfriScam) | 9 | 1.0000 | 0.8889 | 0.9412 | 1.0000 | 0.8750 | 8 | 1 | 0 | 0 |
| English | 1611 | 0.9744 | 0.9946 | 0.9844 | 0.0074 | 0.9971 | 913 | 5 | 24 | 669 |
| Other | 503 | 0.9742 | 1.0000 | 0.9869 | n/a | n/a | 490 | 0 | 13 | 0 |
| Swahili | 853 | 0.9934 | 0.9869 | 0.9902 | 0.0073 | 0.9985 | 302 | 4 | 2 | 545 |

## Kenyan-only (real-world AfriScam rows in the test set)
| Slice | n | Recall | Precision | F1 | FPR | ROC-AUC | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|---|
| Kenya, real-world | 3 | 1.0000 | 1.0000 | 1.0000 | n/a | n/a | 3 | 0 | 0 | 0 |

Only 3 rows, almost all scams: far too few to support a claim. A real Kenyan test set (including legit M-Pesa/bank messages) is still required.

## Leave-one-source-out (transfer check)
The model is retrained without one source and tested on all of that source. This is the honest estimate of performance on data that does not look like the training sources.
| Slice | n | Recall | Precision | F1 | FPR | ROC-AUC | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|---|
| held out: afriscam | 121 | 0.8718 | 0.9714 | 0.9189 | 0.7500 | 0.6197 | 102 | 3 | 15 | 1 |
| held out: bongoscam | 1043 | 0.9177 | 0.9960 | 0.9553 | 0.0040 | 0.9973 | 502 | 2 | 45 | 494 |
| held out: imc25_smishing | 9000 | 0.3539 | 1.0000 | 0.5228 | n/a | n/a | 3185 | 0 | 5815 | 0 |
| held out: ssd_swahili | 4646 | 0.9615 | 0.9399 | 0.9505 | 0.0287 | 0.9890 | 1422 | 91 | 57 | 3076 |
| held out: uci_sms_spam | 5094 | 0.9967 | 0.1219 | 0.2173 | 0.9564 | 0.8071 | 597 | 4299 | 2 | 196 |

## Reading these numbers
- In-distribution scores are high partly because sources differ in language and style (e.g. IMC'25 is all scam). The leave-one-source-out table is the realistic view.
- There are no Kenyan legit messages in the training data, so the false-positive rate on real M-Pesa, bank and OTP messages is unknown.
- The model is binary. Scam categories in the API come from keyword rules, not from this model.
