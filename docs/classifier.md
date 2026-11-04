# Classifier accuracy

agentaudit's optional classifier (`scan --classify`, install `agentaudit[ml]`) flags
tool descriptions that look like prompt injection or exfiltration instructions.
It is **advisory**: its findings are labelled as such and never fail CI.

Decision threshold: **0.231**, chosen on a validation split of the
training data to keep the false-positive rate at or below 1%.

| Evaluation set | Poisoned / benign | Precision | Recall | False-positive rate (95% CI) |
|---|---|---|---|---|
| held-out templated (unseen wording) | 150 / 250 | 98.7% | 98.0% | 0.8% (0.2% to 2.9%) |
| hand-written (realistic style) | 20 / 35 | 83.3% | 100.0% | 11.4% (4.5% to 26.0%) |

## How to read this

- **These numbers are not real-world accuracy.** The training data is synthetic, built
  from templates, and the evaluation sets are small. The held-out templated set uses
  different wording from training but the same overall structure, so it is optimistic.
  The hand-written set is closer to real descriptions but has only a few dozen rows,
  hence the wide confidence interval on the false-positive rate.
- The proposal's target is a published false-positive rate under 10% on real tool
  descriptions. That still needs to be measured on a labelled sample of real MCP servers;
  this page will be updated when it is.
- A determined attacker can phrase an injection to avoid this model. It is a second
  opinion next to the deterministic rules, not a replacement for reviewing tool text.

Reproduce: `uv run python training/build_dataset.py`, `build_handwritten.py`,
`train.py`, then `evaluate.py`.
