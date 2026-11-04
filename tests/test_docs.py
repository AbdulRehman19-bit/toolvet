from pathlib import Path

from agentaudit.rules import load_rules

DOCS = Path(__file__).parent.parent / "docs"


def test_every_rule_is_documented():
    text = (DOCS / "rules.md").read_text(encoding="utf-8")
    for rule in load_rules(plugins=False):
        assert f"## {rule.id} {rule.title}" in text, rule.id
    assert "## AA100 Lethal trifecta" in text


def test_readme_rule_table_lists_every_rule():
    readme = (DOCS.parent / "README.md").read_text(encoding="utf-8")
    for rule in load_rules(plugins=False):
        assert f"| {rule.id} |" in readme, rule.id


def test_classifier_doc_matches_shipped_model():
    import json

    meta = json.loads(
        (DOCS.parent / "src" / "agentaudit" / "ml" / "model.json").read_text(encoding="utf-8")
    )
    text = (DOCS / "classifier.md").read_text(encoding="utf-8")
    assert f"**{meta['threshold']:.3f}**" in text


def test_policy_doc_example_is_a_valid_policy():
    import re
    import tomllib
    from datetime import date

    from agentaudit.policy import parse_policy

    text = (DOCS / "policy.md").read_text(encoding="utf-8")
    block = re.search(r"```toml\n(.*?)```", text, re.DOTALL).group(1)
    policy = parse_policy(tomllib.loads(block), today=date(2026, 11, 4))
    assert len(policy.waivers) == 2 and policy.max_waiver_days == 180


def test_readme_links_are_absolute_so_they_work_on_pypi():
    import re

    readme = (DOCS.parent / "README.md").read_text(encoding="utf-8")
    prose = re.sub(r"```.*?```", "", readme, flags=re.DOTALL)  # code blocks are examples
    targets = re.findall(r"\]\(([^)]+)\)", prose)
    relative = [t for t in targets if not t.startswith(("http://", "https://", "#", "mailto:"))]
    assert relative == []


def test_reported_version_matches_pyproject():
    import tomllib

    import agentaudit

    declared = tomllib.loads((DOCS.parent / "pyproject.toml").read_text(encoding="utf-8"))
    assert agentaudit.__version__ == declared["project"]["version"]
