"""Shared detector contract.

Every detector returns a `DetectorResult` so the risk engine and explainer never
depend on a specific model, and a detector can later move into its own service.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Evidence:
    """One explainable fact behind a score.

    `code` is stable (used for rules and de-duplication); `message` is shown to users;
    `weight` (0..1) orders reasons by importance.
    """

    code: str
    message: str
    weight: float = 0.5


@dataclass(frozen=True)
class DetectorResult:
    """Output of any detector: probability-like score, label, evidence and timing."""

    score: float
    label: str
    evidence: list[Evidence] = field(default_factory=list)
    latency_ms: float = 0.0
    model_version: str = ""
