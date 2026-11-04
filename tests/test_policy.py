import json
from datetime import date, timedelta
from pathlib import Path

import pytest

from toolvet.models import Finding, Severity
from toolvet.policy import (
    Policy,
    PolicyError,
    Waiver,
    apply_policy,
    load_policy,
    matches,
    parse_policy,
    policy_problems,
)
from toolvet.reporters import to_badge, to_json, to_markdown, to_sarif

TODAY = date(2026, 11, 4)
FUTURE = (TODAY + timedelta(days=90)).isoformat()


def finding(rule="TV002", server="mcp:mailer", tool=None, severity=Severity.HIGH) -> Finding:
    return Finding(rule_id=rule, severity=severity, message="m", server=server, tool=tool)


def waiver(**kw) -> dict:
    base = {
        "rule": "TV002",
        "server": "mcp:mailer",
        "reason": "sandbox token",
        "owner": "alice",
        "expires": FUTURE,
    }
    base.update(kw)
    return base


def parse(**data):
    return parse_policy(data, TODAY)


def errors_of(**data) -> str:
    with pytest.raises(PolicyError) as info:
        parse(**data)
    return str(info.value)


def test_empty_policy_is_valid():
    assert parse() == Policy()


def test_full_policy_parses():
    policy = parse(
        fail_on="medium",
        max_waiver_days=30,
        severity={"TV003": "high"},
        waiver=[waiver(expires=(TODAY + timedelta(days=20)).isoformat())],
    )
    assert policy.fail_on is Severity.MEDIUM
    assert policy.severity == {"TV003": Severity.HIGH}
    assert policy.waivers[0].owner == "alice" and policy.max_waiver_days == 30


@pytest.mark.parametrize(
    "data, message",
    [
        ({"nope": 1}, "unknown key 'nope'"),
        ({"fail_on": "severe"}, "fail_on"),
        ({"max_waiver_days": 0}, "max_waiver_days"),
        ({"severity": {"TV999": "high"}}, "unknown rule 'TV999'"),
        ({"severity": {"TV003": "loud"}}, "not a severity"),
        ({"waiver": [waiver(reason="  ")]}, "reason is required"),
        ({"waiver": [waiver(owner="")]}, "owner is required"),
        ({"waiver": [waiver(expires=None)]}, "expires is required"),
        ({"waiver": [waiver(expires="soon")]}, "expires is required"),
        ({"waiver": [waiver(rule="TV777")]}, "unknown or missing rule"),
        ({"waiver": [waiver(server=None)]}, "server is required"),
        ({"waiver": [waiver(color="red")]}, "unknown key 'color'"),
        ({"waiver": [waiver(servers=["x"])]}, "servers is only for TV100"),
        ({"waiver": [waiver(rule="TV100")]}, "must list the exact servers"),
        (
            {"waiver": [waiver(rule="TV100", server=None, servers=[])]},
            "must list the exact servers",
        ),
        ({"waiver": ["text"]}, "must be a table"),
        ({"waiver": {"rule": "TV002"}}, r"\[\[waiver\]\]"),
    ],
)
def test_invalid_policies_are_rejected_with_a_clear_message(data, message):
    assert message in errors_of(**data) or __import__("re").search(message, errors_of(**data))


def test_waiver_horizon_is_capped():
    far = (TODAY + timedelta(days=400)).isoformat()
    assert "more than 365 days away" in errors_of(waiver=[waiver(expires=far)])
    parse(waiver=[waiver(expires=(TODAY + timedelta(days=365)).isoformat())])


def test_all_errors_are_reported_together():
    text = errors_of(fail_on="x", waiver=[waiver(owner=""), waiver(reason="")])
    assert text.count("\n  - ") >= 3


def test_trifecta_waiver_with_server_key_is_rejected():
    text = errors_of(
        waiver=[
            {
                "rule": "TV100",
                "server": "a",
                "servers": ["a"],
                "reason": "r",
                "owner": "o",
                "expires": FUTURE,
            }
        ]
    )
    assert "use servers = [...]" in text


def trifecta_waiver(*servers) -> Waiver:
    policy = parse(
        waiver=[
            {
                "rule": "TV100",
                "servers": list(servers),
                "reason": "sandboxed",
                "owner": "alice",
                "expires": FUTURE,
            }
        ]
    )
    return policy.waivers[0]


def test_trifecta_waiver_covers_only_the_accepted_servers():
    w = trifecta_waiver("mcp:fetch", "mcp:fs", "mcp:mail")
    assert matches(w, finding("TV100", "mcp:fetch, mcp:fs, mcp:mail"))
    assert matches(w, finding("TV100", "mcp:fetch, mcp:fs"))  # narrower is still accepted
    assert not matches(w, finding("TV100", "mcp:fetch, mcp:fs, mcp:mail, mcp:slack"))  # widened


def test_matching_by_server_glob_and_tool():
    w = parse(waiver=[waiver(server="mcp:mail*", tool="send_*")]).waivers[0]
    assert matches(w, finding(server="mcp:mailer", tool="send_email"))
    assert not matches(w, finding(server="mcp:mailer", tool="read"))
    assert not matches(w, finding(server="mcp:mailer", tool=None))
    assert not matches(w, finding(server="mcp:other", tool="send_email"))
    assert not matches(w, finding(rule="TV003", server="mcp:mailer", tool="send_email"))


def test_apply_policy_marks_waived_findings_and_keeps_them():
    policy = parse(waiver=[waiver()])
    out = apply_policy([finding(), finding(server="mcp:other")], policy, TODAY)
    assert len(out) == 2
    assert out[0].waiver == {"reason": "sandbox token", "owner": "alice", "expires": FUTURE}
    assert out[1].waiver is None


def test_expired_waivers_stop_applying():
    policy = parse(waiver=[waiver(expires=TODAY.isoformat())])
    assert apply_policy([finding()], policy, TODAY)[0].waiver is not None
    assert apply_policy([finding()], policy, TODAY + timedelta(days=1))[0].waiver is None


def test_severity_override_applies_before_waivers():
    policy = parse(severity={"TV002": "low"})
    assert apply_policy([finding()], policy, TODAY)[0].severity is Severity.LOW


def test_policy_problems():
    soon = (TODAY + timedelta(days=5)).isoformat()
    policy = parse(
        waiver=[
            waiver(expires=soon),
            waiver(server="mcp:ghost"),
            waiver(server="mcp:old", expires=TODAY.isoformat()),
        ]
    )
    later = TODAY + timedelta(days=1)
    kinds = {(p.kind, p.waiver.server) for p in policy_problems(policy, [finding()], later)}
    assert kinds == {
        ("expiring", "mcp:mailer"),
        ("unused", "mcp:ghost"),
        ("expired", "mcp:old"),
        ("unused", "mcp:old"),
    }
    expired = policy_problems(policy, [finding(server="mcp:old")], TODAY + timedelta(days=2))
    assert ("expired", "mcp:old") in {(p.kind, p.waiver.server) for p in expired}


def test_load_policy_files(tmp_path):
    assert load_policy(tmp_path / "missing.toml", TODAY) == Policy()
    path = tmp_path / "agent.policy.toml"
    path.write_text(
        f'fail_on = "medium"\n\n[[waiver]]\nrule = "TV002"\nserver = "mcp:mailer"\n'
        f'reason = "sandbox"\nowner = "bob"\nexpires = {FUTURE}\n',
        encoding="utf-8",
    )
    policy = load_policy(path, TODAY)
    assert policy.fail_on is Severity.MEDIUM and policy.waivers[0].expires.isoformat() == FUTURE
    path.write_text("not = [valid", encoding="utf-8")
    with pytest.raises(PolicyError, match="not valid TOML"):
        load_policy(path, TODAY)
    path.write_text("unknown = 1\n", encoding="utf-8")
    with pytest.raises(PolicyError, match=r"agent.policy.toml: invalid policy"):
        load_policy(path, TODAY)
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(tmp_path, TODAY)  # a directory


def test_waived_findings_do_not_fail_the_badge_and_appear_in_reports():
    waived = apply_policy([finding()], parse(waiver=[waiver()]), TODAY)
    assert "passing" not in to_badge(waived) and "low-risk" in to_badge(waived)
    sarif = json.loads(to_sarif(waived, Path(".")))
    suppression = sarif["runs"][0]["results"][0]["suppressions"][0]
    assert suppression["kind"] == "external" and suppression["justification"] == "sandbox token"
    assert suppression["properties"]["owner"] == "alice"
    report = json.loads(to_json([], waived, Path(".")))
    assert report["findings"][0]["waiver"]["owner"] == "alice"
    assert "(waived)" in to_markdown([], waived)
