"""Evaluate the shipped ONNX classifier on the held-out sets and write docs/classifier.md.

Metrics are computed with the same runtime code users run (agentaudit.ml.classifier), at
the threshold stored in model.json. The false-positive rate includes a 95% Wilson interval
because the sets are small.

Run:  uv run python training/evaluate.py
"""

from __future__ import annotations

import json
import math
from pathlib import Path

from agentaudit.ml.classifier import Classifier

ROOT = Path(__file__).parent
DOCS = ROOT.parent / "docs"
SETS = {
    "held-out templated (unseen wording)": "test.jsonl",
    "hand-written (realistic style)": "handwritten.jsonl",
}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - margin), min(1.0, centre + margin)


def evaluate(classifier: Classifier, name: str) -> dict:
    rows = [json.loads(l) for l in (ROOT / "data" / name).read_text("utf-8").splitlines()]
    tp = fp = tn = fn = 0
    misses, false_alarms = [], []
    for row in rows:
        flagged = classifier.is_suspicious(row["text"])
        if row["label"] == 1:
            tp, fn = tp + flagged, fn + (not flagged)
            if not flagged:
                misses.append(row["text"])
        else:
            fp, tn = fp + flagged, tn + (not flagged)
            if flagged:
                false_alarms.append(row["text"])
    low, high = wilson(fp, fp + tn)
    return {
        "n": len(rows),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else 1.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "fpr_ci": (low, high),
        "misses": misses,
        "false_alarms": false_alarms,
    }


def main() -> None:
    classifier = Classifier()
    results = {label: evaluate(classifier, f) for label, f in SETS.items()}
    lines = [
        "# Classifier accuracy",
        "",
        "agentaudit's optional classifier (`scan --classify`, install `agentaudit[ml]`) flags",
        "tool descriptions that look like prompt injection or exfiltration instructions.",
        "It is **advisory**: its findings are labelled as such and never fail CI.",
        "",
        f"Decision threshold: **{classifier.threshold:.3f}**, chosen on a validation pool whose",
        "wording is unseen in training, to keep the false-positive rate at or below 1%.",
        "",
        "| Evaluation set | Poisoned / benign | Precision | Recall | False-positive rate (95% CI) |",
        "|---|---|---|---|---|",
    ]
    for label, r in results.items():
        bad, good = r["tp"] + r["fn"], r["fp"] + r["tn"]
        lo, hi = r["fpr_ci"]
        lines.append(
            f"| {label} | {bad} / {good} | {r['precision']:.1%} | {r['recall']:.1%} | "
            f"{r['fpr']:.1%} ({lo:.1%} to {hi:.1%}) |"
        )
    lines += [
        "",
        "## How to read this",
        "",
        "- **These numbers are not real-world accuracy.** The training data is synthetic, built",
        "  from templates, and the evaluation sets are small. The held-out templated set uses",
        "  different wording from training but the same overall structure, so it is optimistic.",
        "  The hand-written set is closer to real descriptions but has only a few dozen rows,",
        "  hence the wide confidence interval on the false-positive rate.",
        "- The hand-written set was looked at once to diagnose an earlier, overfitted model",
        "  (it had a 60% false-positive rate there). The training data was then broadened and",
        "  the threshold re-chosen on separate validation data; nothing was tuned against the",
        "  hand-written set afterwards, but treat its numbers as slightly optimistic.",
        "- The proposal's target is a published false-positive rate under 10% on real tool",
        "  descriptions. That still needs to be measured on a labelled sample of real MCP servers;",
        "  this page will be updated when it is.",
        "- A determined attacker can phrase an injection to avoid this model. It is a second",
        "  opinion next to the deterministic rules, not a replacement for reviewing tool text.",
        "",
        "Reproduce: `uv run python training/build_dataset.py`, `build_handwritten.py`,",
        "`train.py`, then `evaluate.py`.",
        "",
    ]
    (DOCS / "classifier.md").write_text("\n".join(lines), encoding="utf-8")
    for label, r in results.items():
        print(
            f"{label}: precision {r['precision']:.3f} recall {r['recall']:.3f} "
            f"fpr {r['fpr']:.3f} (fp={r['fp']}, fn={r['fn']})"
        )
        for text in r["misses"][:6]:
            print("  MISSED:", text[:150])
        for text in r["false_alarms"][:6]:
            print("  FALSE ALARM:", text[:150])


if __name__ == "__main__":
    main()
