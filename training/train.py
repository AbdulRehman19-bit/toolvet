"""Train the tool-description classifier and export it to ONNX.

Hyperparameters and the decision threshold are chosen on a validation split taken from the
*training* data. The test and hand-written sets are never touched here (see evaluate.py).
The threshold is the lowest score that keeps the validation false-positive rate at or below
TARGET_FPR, because false positives are what make users switch a tool off.

Run:  uv run python training/train.py
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

from agentaudit.ml.features import DIM, featurize

ROOT = Path(__file__).parent
MODEL_DIR = ROOT.parent / "src" / "agentaudit" / "ml"
TARGET_FPR = 0.01
SEED = 7


def load(name: str) -> tuple[np.ndarray, np.ndarray]:
    rows = [json.loads(line) for line in (ROOT / "data" / name).read_text("utf-8").splitlines()]
    x = np.array([featurize(r["text"]) for r in rows], dtype=np.float32)
    return x, np.array([r["label"] for r in rows])


def pick_threshold(scores: np.ndarray, labels: np.ndarray) -> tuple[float, float, float]:
    """Lowest threshold whose validation FPR <= TARGET_FPR. Returns (threshold, recall, fpr)."""
    benign, bad = scores[labels == 0], scores[labels == 1]
    best = (1.0, 0.0, 0.0)
    for t in sorted({*scores.tolist(), 0.5}):
        fpr = float((benign >= t).mean())
        if fpr <= TARGET_FPR:
            return float(t), float((bad >= t).mean()), fpr
    return best


HANDWRITTEN_WEIGHT = 4.0


def main() -> None:
    x_tpl, y_tpl = load("train.jsonl")
    x_hw, y_hw = load("handwritten_train.jsonl")
    x_hw_fit, x_hw_dev, y_hw_fit, y_hw_dev = train_test_split(
        x_hw, y_hw, test_size=0.3, stratify=y_hw, random_state=SEED
    )
    x_pool, y_pool = load("val.jsonl")  # unseen wording: used only to choose C and threshold
    x_fit = np.vstack([x_tpl, x_hw_fit])
    y_fit = np.concatenate([y_tpl, y_hw_fit])
    weights = np.concatenate([np.ones(len(y_tpl)), np.full(len(y_hw_fit), HANDWRITTEN_WEIGHT)])
    x_val = np.vstack([x_pool, x_hw_dev])
    y_val = np.concatenate([y_pool, y_hw_dev])

    best = None
    for c in (0.5, 1.0, 2.0, 5.0, 10.0, 20.0):
        model = LogisticRegression(C=c, max_iter=2000, random_state=SEED)
        model.fit(x_fit, y_fit, sample_weight=weights)
        scores = model.predict_proba(x_val)[:, 1]
        auc = roc_auc_score(y_val, scores)
        threshold, recall, fpr = pick_threshold(scores, y_val)
        print(
            f"C={c:<5} val auc={auc:.4f} recall={recall:.3f} fpr={fpr:.3f} threshold={threshold:.3f}"
        )
        if best is None or auc > best[0] + 1e-6:
            best = (auc, c, threshold, recall, model)
    auc, c, threshold, recall, model = best
    print(f"chosen C={c}, threshold={threshold:.4f} (val auc {auc:.4f}, recall {recall:.3f})")

    onnx_model = convert_sklearn(
        model,
        initial_types=[("features", FloatTensorType([None, DIM]))],
        options={id(model): {"zipmap": False}},
        target_opset=15,
    )
    (MODEL_DIR / "model.onnx").write_bytes(onnx_model.SerializeToString())

    import onnxruntime as ort

    session = ort.InferenceSession(
        str(MODEL_DIR / "model.onnx"), providers=["CPUExecutionProvider"]
    )
    onnx_scores = session.run(None, {"features": x_val})[1][:, 1]
    drift = float(np.abs(onnx_scores - model.predict_proba(x_val)[:, 1]).max())
    assert drift < 1e-4, f"ONNX output differs from scikit-learn by {drift}"

    meta = {
        "model_version": 1,
        "dim": DIM,
        "threshold": round(threshold, 6),
        "C": c,
        "target_validation_fpr": TARGET_FPR,
        "train_rows": int(len(y_fit)),
        "validation_rows": int(len(y_val)),
    }
    (MODEL_DIR / "model.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    size_kb = (MODEL_DIR / "model.onnx").stat().st_size / 1024
    print(f"wrote model.onnx ({size_kb:.0f} KB), max ONNX/sklearn drift {drift:.2e}")


if __name__ == "__main__":
    main()
