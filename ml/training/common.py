"""Shared helpers for training scripts: config loading, metrics, MLflow logging, reports."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import numpy as np
import yaml
from sklearn.metrics import confusion_matrix, roc_auc_score

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def binary_metrics(y_true, y_prob, threshold: float = 0.5) -> dict:
    """Headline metrics. Positive class = scam/malicious."""
    y_true = np.asarray(y_true).astype(int)
    y_prob = np.asarray(y_prob, dtype=float)
    y_pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    recall = tp / (tp + fn) if tp + fn else float("nan")
    precision = tp / (tp + fp) if tp + fp else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else float("nan")
    fpr = fp / (fp + tn) if fp + tn else float("nan")
    auc = roc_auc_score(y_true, y_prob) if len(set(y_true.tolist())) == 2 else float("nan")
    return {
        "n": int(len(y_true)), "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
        "recall": float(recall), "precision": float(precision), "f1": float(f1),
        "fpr": float(fpr), "roc_auc": float(auc),
    }  # fmt: skip


def fmt(value: float) -> str:
    return "n/a" if value != value else f"{value:.4f}"  # NaN check


def metrics_row(name: str, m: dict) -> str:
    return (
        f"| {name} | {m['n']} | {fmt(m['recall'])} | {fmt(m['precision'])} | {fmt(m['f1'])} "
        f"| {fmt(m['fpr'])} | {fmt(m['roc_auc'])} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} |"
    )


METRICS_HEADER = (
    "| Slice | n | Recall | Precision | F1 | FPR | ROC-AUC | TP | FP | FN | TN |\n"
    "|---|---|---|---|---|---|---|---|---|---|---|"
)


def log_mlflow(experiment: str, run_name: str, params: dict, metrics: dict, artifact: str) -> None:
    """Log one run to MLflow. Uses ./mlflow.db unless MLFLOW_TRACKING_URI is set. Never fatal."""
    try:
        # No usage telemetry: training metadata stays on this machine.
        os.environ.setdefault("MLFLOW_DISABLE_TELEMETRY", "true")
        os.environ.setdefault("DO_NOT_TRACK", "true")
        import mlflow

        mlflow.set_tracking_uri(
            os.environ.get("MLFLOW_TRACKING_URI", f"sqlite:///{REPO_ROOT}/mlflow.db")
        )
        mlflow.set_experiment(experiment)
        with mlflow.start_run(run_name=run_name):
            mlflow.log_params({k: str(v)[:250] for k, v in params.items()})
            mlflow.log_metrics({k: v for k, v in metrics.items() if v == v})
            if Path(artifact).exists() and Path(artifact).stat().st_size < 50_000_000:
                mlflow.log_artifact(artifact)
    except Exception as exc:  # noqa: BLE001 - tracking must not lose a trained model
        print(f"[warn] MLflow logging skipped: {type(exc).__name__}: {exc}")
