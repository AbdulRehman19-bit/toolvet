"""Local ONNX classifier for suspicious tool descriptions. Opt-in and advisory only.

Runs entirely on this machine; no text is sent anywhere. Findings it produces are marked
advisory and never fail CI.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentaudit.ml.features import DIM, featurize
from agentaudit.models import Finding, Server, Severity

MODEL_DIR = Path(__file__).parent
RULE_ID = "ML001"
WINDOW = 600
STRIDE = 300


class MLUnavailable(RuntimeError):
    """The optional ML dependencies are not installed."""


class Classifier:
    def __init__(self, model_path: Path | None = None, threshold: float | None = None):
        try:
            import numpy
            import onnxruntime
        except ImportError as exc:
            raise MLUnavailable(
                "The classifier needs optional dependencies: pip install 'agentaudit[ml]'"
            ) from exc
        self._np = numpy
        meta = json.loads((MODEL_DIR / "model.json").read_text(encoding="utf-8"))
        if meta["dim"] != DIM:
            raise ValueError("model.json does not match the feature size; retrain the model")
        self.threshold = meta["threshold"] if threshold is None else threshold
        path = model_path or MODEL_DIR / "model.onnx"
        self._session = onnxruntime.InferenceSession(str(path), providers=["CPUExecutionProvider"])

    def _score_one(self, text: str) -> float:
        features = self._np.array([featurize(text)], dtype=self._np.float32)
        probabilities = self._session.run(None, {"features": features})[1]
        return float(probabilities[0][1])

    def score(self, text: str) -> float:
        """Probability that `text` is a poisoned description. Long text is scored in
        overlapping windows and the highest score wins, so a buried payload is not diluted."""
        if len(text) <= WINDOW:
            return self._score_one(text)
        starts = range(0, len(text) - WINDOW + STRIDE, STRIDE)
        return max(self._score_one(text[i : i + WINDOW]) for i in starts)

    def is_suspicious(self, text: str) -> bool:
        return self.score(text) >= self.threshold


def classify_servers(servers: list[Server], classifier: Classifier) -> list[Finding]:
    """Score every tool description. Returns advisory findings for suspicious ones."""
    findings = []
    for server in servers:
        for tool in server.tools:
            if not tool.description.strip():
                continue
            score = classifier.score(tool.description)
            if score >= classifier.threshold:
                findings.append(
                    Finding(
                        rule_id=RULE_ID,
                        severity=Severity.MEDIUM,
                        message=(
                            f"Classifier scored this tool description {score:.2f} "
                            f"(flag threshold {classifier.threshold:.2f}); review it by hand"
                        ),
                        server=server.id,
                        tool=tool.name,
                        source=server.source,
                        evidence=[tool.description[:160]],
                        advisory=True,
                    )
                )
    return findings
