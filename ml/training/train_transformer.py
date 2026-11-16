"""Fine-tune a multilingual transformer (AfroXLMR) for scam detection.

STATUS: NOT RUN. This needs a GPU (e.g. Google Colab) and `pip install torch transformers
datasets`, none of which were available where the rest of this project was built. Treat it as
a starting point: run it, fix what breaks, and record real metrics before citing any.

After training, compare with the baseline on the validation set, export the better model, and
add a transformer branch to `backend/app/detectors/text_detector.py` behind the same
`predict(text) -> DetectorResult` interface.

Usage (Colab): python -m ml.training.train_transformer --config ml/configs/text_transformer.yaml
"""

from __future__ import annotations

import argparse

import numpy as np
import pandas as pd

from ml.training.common import REPO_ROOT, binary_metrics, load_config, log_mlflow


def main() -> None:
    from datasets import Dataset
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        DataCollatorWithPadding,
        Trainer,
        TrainingArguments,
    )

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--config", default="ml/configs/text_transformer.yaml")
    cfg = load_config(parser.parse_args().config)

    train = pd.read_csv(REPO_ROOT / cfg["train"], low_memory=False)
    extra = REPO_ROOT / cfg.get("extra_train", "")
    if cfg.get("extra_train") and extra.exists():
        train = pd.concat([train, pd.read_csv(extra, low_memory=False)], ignore_index=True)
    val = pd.read_csv(REPO_ROOT / cfg["val"], low_memory=False)

    tokenizer = AutoTokenizer.from_pretrained(cfg["base_model"])

    def encode(frame: pd.DataFrame) -> Dataset:
        ds = Dataset.from_dict(
            {"text": frame["text"].astype(str).tolist(), "label": frame["is_malicious"].tolist()}
        )
        return ds.map(
            lambda batch: tokenizer(batch["text"], truncation=True, max_length=cfg["max_length"]),
            batched=True,
        )

    def compute(eval_pred) -> dict:
        logits, labels = eval_pred
        exp = np.exp(logits - logits.max(axis=1, keepdims=True))
        prob = (exp / exp.sum(axis=1, keepdims=True))[:, 1]
        m = binary_metrics(labels, prob)
        return {k: m[k] for k in ("recall", "precision", "f1", "fpr", "roc_auc")}

    model = AutoModelForSequenceClassification.from_pretrained(cfg["base_model"], num_labels=2)
    out_dir = str(REPO_ROOT / cfg["output_dir"])
    trainer = Trainer(
        model=model,
        args=TrainingArguments(
            output_dir=out_dir,
            num_train_epochs=cfg["epochs"],
            per_device_train_batch_size=cfg["batch_size"],
            per_device_eval_batch_size=cfg["batch_size"] * 2,
            learning_rate=cfg["learning_rate"],
            eval_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="f1",
            seed=cfg["seed"],
            report_to=[],
        ),
        train_dataset=encode(train),
        eval_dataset=encode(val),
        data_collator=DataCollatorWithPadding(tokenizer),
        compute_metrics=compute,
    )
    trainer.train()
    metrics = {k.replace("eval_", "val_"): v for k, v in trainer.evaluate().items()}
    trainer.save_model(out_dir)
    tokenizer.save_pretrained(out_dir)
    print(metrics)
    log_mlflow("jasusi-text", cfg["version"], cfg, {k: float(v) for k, v in metrics.items()}, "")


if __name__ == "__main__":
    main()
