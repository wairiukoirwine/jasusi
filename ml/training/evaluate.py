"""Evaluate the trained models on the frozen test sets and write Markdown reports.

Reports contain numbers only (no message text) so they are safe to commit:
  docs/reports/text_baseline.md, docs/reports/url_model.md

For the text model the report also includes a leave-one-source-out check. Most public
sources contain a single class, so in-distribution scores can be inflated by the model
recognising the *source*. Holding a whole source out shows how well it transfers.

Usage: python -m ml.training.evaluate [--skip-loso]
"""

from __future__ import annotations

import argparse
import time
from datetime import UTC, datetime

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

from ml.training.common import (
    METRICS_HEADER,
    REPO_ROOT,
    binary_metrics,
    fmt,
    load_config,
    metrics_row,
)
from ml.training.train_text import build_pipeline
from ml.training.train_url import to_dmatrix

REPORTS = REPO_ROOT / "docs" / "reports"


def _latency_ms(predict_one, samples: list[str]) -> tuple[float, float]:
    times = []
    for s in samples:
        t0 = time.perf_counter()
        predict_one(s)
        times.append((time.perf_counter() - t0) * 1000)
    return float(np.percentile(times, 50)), float(np.percentile(times, 95))


def _slices(frame: pd.DataFrame, prob: np.ndarray, column: str, min_n: int = 1) -> list[str]:
    rows = []
    for value, idx in frame.groupby(column, sort=True).indices.items():
        if len(idx) >= min_n:
            rows.append(
                metrics_row(str(value), binary_metrics(frame["is_malicious"].iloc[idx], prob[idx]))
            )
    return rows


def evaluate_text(skip_loso: bool) -> None:
    cfg = load_config(str(REPO_ROOT / "ml/configs/text_baseline.yaml"))
    bundle = joblib.load(REPO_ROOT / cfg["output"])
    pipeline = bundle["pipeline"]
    test = pd.read_csv(REPO_ROOT / cfg["test"], low_memory=False).reset_index(drop=True)
    texts = test["text"].astype(str)
    prob = pipeline.predict_proba(texts)[:, 1]
    overall = binary_metrics(test["is_malicious"], prob)
    p50, p95 = _latency_ms(
        lambda s: pipeline.predict_proba([s]), texts.sample(500, random_state=42).tolist()
    )

    kenya = test["country"].fillna("").eq("KE") & test["origin"].eq("real_world")

    def lang_group(v: str) -> str:
        if v == "sw":
            return "Swahili"
        if v == "English":
            return "English"
        return "EN/SW/Sheng mix (AfriScam)" if "+" in v or v in {"en", "sheng"} else "Other"

    lang = test["language"].fillna("").astype(str).map(lang_group)
    lines = [
        "# Text baseline — test-set report",
        "",
        f"Model `{bundle['version']}` (TF-IDF word+char n-grams, Logistic Regression, C={bundle['C']}), "
        f"trained {bundle['trained_at']} on {bundle['train_rows']} messages "
        f"({bundle.get('synthetic_train_rows', 0)} of them synthetic Kenyan legit messages, training only).",
        f"Generated {datetime.now(UTC).isoformat(timespec='seconds')} by `python -m ml.training.evaluate`.",
        "Positive class = scam or spam. Threshold 0.5. Test set is frozen (`ml/configs/splits_v1.lock.json`).",
        "",
        "## Headline (frozen test set)",
        METRICS_HEADER,
        metrics_row("All test messages", overall),
        "",
        f"Single-message CPU latency: p50 {p50:.1f} ms, p95 {p95:.1f} ms (target p95 < 300 ms).",
        "",
        "## By original label",
        "Recall is the meaningful column for `scam` and `spam`; FPR for `legit`.",
        METRICS_HEADER,
        *_slices(test, prob, "label"),
        "",
        "## By source",
        METRICS_HEADER,
        *_slices(test, prob, "source"),
        "",
        "## By language group",
        METRICS_HEADER,
        *_slices(test.assign(lang=lang), prob, "lang"),
        "",
        "## Kenyan-only (real-world AfriScam rows in the test set)",
    ]
    if kenya.sum():
        lines += [METRICS_HEADER, metrics_row("Kenya, real-world", binary_metrics(test["is_malicious"][kenya], prob[kenya])),
                  "", f"Only {int(kenya.sum())} rows, almost all scams: far too few to support a claim. "
                  "A real Kenyan test set (including legit M-Pesa/bank messages) is still required."]  # fmt: skip
    else:
        lines.append("No Kenyan real-world rows landed in the test set.")

    if not skip_loso:
        full = pd.concat(
            [pd.read_csv(REPO_ROOT / cfg[k], low_memory=False) for k in ("train", "val", "test")],
            ignore_index=True,
        )
        extra = cfg.get("extra_train")
        synth = (
            pd.read_csv(REPO_ROOT / extra, low_memory=False)
            if extra and (REPO_ROOT / extra).exists()
            else full.iloc[0:0]
        )
        lines += [
            "",
            "## Leave-one-source-out (transfer check)",
            "The model is retrained without one source and tested on all of that source. "
            "This is the honest estimate of performance on data that does not look like the training sources.",
            METRICS_HEADER,
        ]
        for source in sorted(full["source"].unique()):
            held = full[full["source"] == source]
            rest = pd.concat([full[full["source"] != source], synth], ignore_index=True)
            model = build_pipeline(cfg, bundle["C"]).fit(
                rest["text"].astype(str), rest["is_malicious"]
            )
            held_prob = model.predict_proba(held["text"].astype(str))[:, 1]
            lines.append(
                metrics_row(f"held out: {source}", binary_metrics(held["is_malicious"], held_prob))
            )
            print(f"LOSO {source} done")

    lines += [
        "",
        "## Reading these numbers",
        "- In-distribution scores are high partly because sources differ in language and style "
        "(e.g. IMC'25 is all scam). The leave-one-source-out table is the realistic view.",
        "- There are no Kenyan legit messages in the training data, so the false-positive rate on real "
        "M-Pesa, bank and OTP messages is unknown.",
        "- The model is binary. Scam categories in the API come from keyword rules, not from this model.",
    ]
    (REPORTS / "text_baseline.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(
        f"text: recall={fmt(overall['recall'])} f1={fmt(overall['f1'])} fpr={fmt(overall['fpr'])}"
    )


def evaluate_url() -> None:
    cfg = load_config(str(REPO_ROOT / "ml/configs/url_xgb.yaml"))
    booster = xgb.Booster()
    booster.load_model(str(REPO_ROOT / cfg["output"]))
    test = pd.read_csv(REPO_ROOT / cfg["test"], low_memory=False).reset_index(drop=True)
    dtest = to_dmatrix(test)
    prob = booster.predict(dtest)
    overall = binary_metrics(test["is_malicious"], prob)
    gain = booster.get_score(importance_type="gain")
    top = sorted(gain.items(), key=lambda kv: kv[1], reverse=True)[:10]
    # Mean |TreeSHAP| on a sample: which features move predictions most.
    sample = dtest.slice(np.random.default_rng(42).choice(len(test), 5000, replace=False))
    shap = np.abs(booster.predict(sample, pred_contribs=True)[:, :-1]).mean(axis=0)
    shap_top = sorted(zip(shap, dtest.feature_names, strict=True), reverse=True)[:10]
    year = test["date"].astype(str).str[:4].where(test["source"].eq("jpcert_phishurl"), "n/a")

    lines = [
        "# URL model — test-set report",
        "",
        f"Model `{booster.attr('version')}` (XGBoost on {len(dtest.feature_names)} lexical features, "
        f"{booster.num_boosted_rounds()} trees).",
        f"Generated {datetime.now(UTC).isoformat(timespec='seconds')} by `python -m ml.training.evaluate`.",
        "Positive class = malicious. Threshold 0.5. Split by registered domain, test set frozen.",
        "",
        "## Headline (frozen test set)",
        METRICS_HEADER,
        metrics_row("All test URLs", overall),
        "",
        "## Recall at fixed false-positive rates",
        "| Target FPR | Threshold | Recall |",
        "|---|---|---|",
    ]
    legit_scores = np.sort(prob[test["is_malicious"].to_numpy() == 0])
    for target in (0.01, 0.05, 0.10):
        threshold = float(legit_scores[int(len(legit_scores) * (1 - target))])
        recall = float((prob[test["is_malicious"].to_numpy() == 1] >= threshold).mean())
        lines.append(f"| {target:.0%} | {threshold:.3f} | {recall:.4f} |")
    lines += [
        "",
        "## By source",
        METRICS_HEADER,
        *_slices(test, prob, "source"),
        "",
        "## JPCERT phishing recall by year reported",
        METRICS_HEADER,
        *_slices(test.assign(year=year)[year != "n/a"], prob[(year != "n/a").to_numpy()], "year"),
        "",
        "## Most influential features (mean |SHAP| on 5,000 test URLs)",
        "| Feature | mean abs SHAP |",
        "|---|---|",
        *[f"| `{name}` | {value:.3f} |" for value, name in shap_top],
        "",
        "## Top features by gain",
        "| Feature | gain |",
        "|---|---|",
        *[f"| `{name}` | {value:.1f} |" for name, value in top],
        "",
        "## Reading these numbers",
        "- Legit URLs come from one 2017-era list and phishing URLs mostly from JPCERT (Japan-heavy "
        "brands), so part of the separation is source style. Fresh legit domains (e.g. Tranco) and "
        "Kenyan phishing URLs are needed before trusting this in the field.",
        "- Lexical features cannot see page content; a clean-looking URL on a compromised site will pass. "
        "Threat intelligence covers part of that gap.",
    ]
    (REPORTS / "url_model.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(
        f"url: recall={fmt(overall['recall'])} fpr={fmt(overall['fpr'])} auc={fmt(overall['roc_auc'])}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--skip-loso", action="store_true")
    args = parser.parse_args()
    REPORTS.mkdir(parents=True, exist_ok=True)
    evaluate_text(args.skip_loso)
    evaluate_url()


if __name__ == "__main__":
    main()
