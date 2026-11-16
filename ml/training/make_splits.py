"""Create the frozen train/val/test splits (70/15/15, seed 42) for SMS and URLs.

Leakage controls:
- SMS: messages that share a template (same text once numbers and links are blanked)
  are collapsed to one row before splitting, so a scam template cannot sit in both
  train and test. Synthetic rows are never placed in validation or test.
- URLs: split by registered domain, so one phishing site's many URLs stay in one split.

The test files are frozen: the script refuses to overwrite them unless --force is given,
and writes their SHA-256 to the lock file so later changes are detectable.

Usage: python -m ml.training.make_splits [--config ml/configs/splits.yaml] [--force]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

import numpy as np
import pandas as pd

from ml.features.url_features import registered_domain, split
from ml.training.common import REPO_ROOT, load_config

_URL_RE = re.compile(r"(?i)(?:https?://|www\.)\S+")


def template_key(text: str) -> str:
    """Normalise a message to its template: links and digits blanked, punctuation dropped."""
    t = _URL_RE.sub(" url ", str(text).lower())
    t = re.sub(r"\d+", "0", t)
    return re.sub(r"\W+", " ", t).strip()


def cap_sources(df: pd.DataFrame, caps: dict[str, int], seed: int) -> pd.DataFrame:
    parts = []
    for source, group in df.groupby("source", sort=True):
        limit = caps.get(source)
        parts.append(
            group.sample(n=limit, random_state=seed) if limit and len(group) > limit else group
        )
    return pd.concat(parts).sort_index()


def stratified_assign(strata: pd.Series, fractions: dict, seed: int) -> pd.Series:
    """Assign each row to train/val/test within its stratum, deterministically."""
    rng = np.random.default_rng(seed)
    out = pd.Series("train", index=strata.index)
    for _, idx in strata.groupby(strata, sort=True).groups.items():
        order = rng.permutation(np.asarray(idx))
        n_test = int(round(len(order) * fractions["test"]))
        n_val = int(round(len(order) * fractions["val"]))
        out.loc[order[:n_test]] = "test"
        out.loc[order[n_test : n_test + n_val]] = "val"
    return out


def split_sms(cfg: dict) -> dict[str, pd.DataFrame]:
    df = pd.read_csv(REPO_ROOT / cfg["sms"]["input"], low_memory=False)
    df["template"] = df["text"].map(template_key)
    df = df[df["template"].str.len() > 0].drop_duplicates("template")
    df = cap_sources(df, cfg["sms"].get("max_rows_per_source", {}), cfg["seed"]).reset_index(
        drop=True
    )
    strata = df["source"] + "|" + df["label"]
    small = strata.map(strata.value_counts()) < 20
    strata[small] = "small|" + df.loc[small, "label"]
    df["split"] = stratified_assign(strata, cfg["fractions"], cfg["seed"])
    df.loc[df["origin"] == "synthetic", "split"] = "train"
    df = df.drop(columns="template")
    return {
        name: df[df["split"] == name].drop(columns="split") for name in ("train", "val", "test")
    }


def split_urls(cfg: dict) -> dict[str, pd.DataFrame]:
    df = pd.read_csv(REPO_ROOT / cfg["urls"]["input"], low_memory=False)
    df = cap_sources(df, cfg["urls"].get("max_rows_per_source", {}), cfg["seed"]).reset_index(
        drop=True
    )
    df["domain"] = df["url"].astype(str).map(lambda u: registered_domain(split(u)[0]))
    domains = df.groupby("domain", sort=True)["is_malicious"].max().reset_index()
    domains["split"] = stratified_assign(
        domains["is_malicious"].astype(str), cfg["fractions"], cfg["seed"]
    )
    df = df.merge(domains[["domain", "split"]], on="domain")
    return {
        name: df[df["split"] == name].drop(columns="split") for name in ("train", "val", "test")
    }


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--config", default="ml/configs/splits.yaml")
    parser.add_argument("--force", action="store_true", help="overwrite frozen splits")
    args = parser.parse_args()
    cfg = load_config(args.config)
    out_dir = REPO_ROOT / cfg["output_dir"]
    if (out_dir / "sms_test_v1.csv").exists() and not args.force:
        raise SystemExit("Splits already exist and the test set is frozen. Use --force to rebuild.")

    lock: dict = {"seed": cfg["seed"], "fractions": cfg["fractions"], "files": {}}
    for kind, parts in (("sms", split_sms(cfg)), ("urls", split_urls(cfg))):
        for name, frame in parts.items():
            path = out_dir / f"{kind}_{name}_v1.csv"
            frame.to_csv(path, index=False)
            lock["files"][path.name] = {
                "rows": int(len(frame)),
                "malicious": int(frame["is_malicious"].sum()),
                "sha256": sha256(path),
            }
            print(f"{path.name}: {len(frame)} rows, {int(frame['is_malicious'].sum())} malicious")
    lock_path = REPO_ROOT / cfg["lock_file"]
    lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    print(f"Lock written to {lock_path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
