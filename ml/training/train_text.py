"""Train the text baseline: TF-IDF (word + character n-grams) + Logistic Regression.

Target is binary: 1 = scam or spam, 0 = legit. The regularisation strength is chosen on
the validation set; the test set is only touched by `evaluate.py`.

Usage: python -m ml.training.train_text --config ml/configs/text_baseline.yaml
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from ml.training.common import REPO_ROOT, binary_metrics, load_config, log_mlflow


def build_pipeline(cfg: dict, c: float) -> Pipeline:
    word = TfidfVectorizer(ngram_range=tuple(cfg["word_ngrams"]), min_df=2, sublinear_tf=True)
    char = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=tuple(cfg["char_ngrams"]),
        min_df=3,
        sublinear_tf=True,
        max_features=cfg["max_char_features"],
    )
    # Word features come first: the API reads their coefficients to explain verdicts.
    features = FeatureUnion([("word", word), ("char", char)])
    clf = LogisticRegression(C=c, class_weight="balanced", max_iter=3000, random_state=cfg["seed"])
    return Pipeline([("features", features), ("clf", clf)])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--config", default="ml/configs/text_baseline.yaml")
    args = parser.parse_args()
    cfg = load_config(args.config)

    train = pd.read_csv(REPO_ROOT / cfg["train"], low_memory=False)
    val = pd.read_csv(REPO_ROOT / cfg["val"], low_memory=False)
    synthetic_rows = 0
    extra = cfg.get("extra_train")
    if extra and (REPO_ROOT / extra).exists():
        extra_frame = pd.read_csv(REPO_ROOT / extra, low_memory=False)
        synthetic_rows = len(extra_frame)
        train = pd.concat([train, extra_frame], ignore_index=True)
        print(f"Added {synthetic_rows} synthetic training rows from {extra}")
    best = None
    for c in cfg["c_grid"]:
        pipeline = build_pipeline(cfg, c).fit(train["text"].astype(str), train["is_malicious"])
        m = binary_metrics(
            val["is_malicious"], pipeline.predict_proba(val["text"].astype(str))[:, 1]
        )
        print(f"C={c}: val recall={m['recall']:.4f} f1={m['f1']:.4f} fpr={m['fpr']:.4f}")
        if best is None or m["f1"] > best[2]["f1"]:
            best = (c, pipeline, m)
    c, pipeline, val_metrics = best

    out = REPO_ROOT / cfg["output"]
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "pipeline": pipeline,
            "version": cfg["version"],
            "trained_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "C": c,
            "val_metrics": val_metrics,
            "train_rows": int(len(train)),
            "synthetic_train_rows": int(synthetic_rows),
        },
        out,
        compress=3,
    )
    print(f"Saved {Path(cfg['output'])} (C={c}, {out.stat().st_size / 1e6:.1f} MB)")
    log_mlflow("jasusi-text", cfg["version"], {**cfg, "chosen_C": c},
               {f"val_{k}": v for k, v in val_metrics.items()}, str(out))  # fmt: skip


if __name__ == "__main__":
    main()
