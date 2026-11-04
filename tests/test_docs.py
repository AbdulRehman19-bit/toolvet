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
