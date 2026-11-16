"""Train the URL phishing model: lexical features (ml/features/url_features.py) + XGBoost.

Usage: python -m ml.training.train_url --config ml/configs/url_xgb.yaml
"""

from __future__ import annotations

import argparse

import numpy as np
import pandas as pd
import xgboost as xgb

from ml.features import url_features
from ml.training.common import REPO_ROOT, binary_metrics, load_config, log_mlflow


def featurise(urls: pd.Series) -> np.ndarray:
    """Same function the API uses at inference time."""
    return np.asarray([url_features.to_vector(str(u)) for u in urls], dtype=np.float32)


def to_dmatrix(frame: pd.DataFrame) -> xgb.DMatrix:
    return xgb.DMatrix(
        featurise(frame["url"]),
        label=frame["is_malicious"],
        feature_names=url_features.FEATURE_NAMES,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--config", default="ml/configs/url_xgb.yaml")
    args = parser.parse_args()
    cfg = load_config(args.config)

    train = pd.read_csv(REPO_ROOT / cfg["train"], low_memory=False)
    val = pd.read_csv(REPO_ROOT / cfg["val"], low_memory=False)
    dtrain, dval = to_dmatrix(train), to_dmatrix(val)
    negatives, positives = (train["is_malicious"] == 0).sum(), (train["is_malicious"] == 1).sum()
    params = {
        **cfg["params"],
        "objective": "binary:logistic",
        "eval_metric": "auc",
        "tree_method": "hist",
        "scale_pos_weight": float(negatives / positives),
        "seed": cfg["seed"],
    }
    booster = xgb.train(
        params, dtrain, num_boost_round=cfg["num_boost_round"], evals=[(dval, "val")],
        early_stopping_rounds=cfg["early_stopping_rounds"], verbose_eval=50,
    )  # fmt: skip
    booster.set_attr(version=cfg["version"])
    val_metrics = binary_metrics(val["is_malicious"], booster.predict(dval))
    print(f"val: recall={val_metrics['recall']:.4f} fpr={val_metrics['fpr']:.4f} "
          f"auc={val_metrics['roc_auc']:.4f} trees={booster.best_iteration + 1}")  # fmt: skip

    out = REPO_ROOT / cfg["output"]
    out.parent.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(out))
    print(f"Saved {cfg['output']} ({out.stat().st_size / 1e6:.1f} MB)")
    log_mlflow("jasusi-url", cfg["version"], {**params, "train_rows": len(train)},
               {f"val_{k}": v for k, v in val_metrics.items()}, str(out))  # fmt: skip


if __name__ == "__main__":
    main()
