import dataclasses
import itertools
import random
from pathlib import Path

import pytest

from toolvet.fixes import FixOption, has_trifecta, layers_of, trifecta_fixes
from toolvet.graph import find_trifectas
from toolvet.models import Capability, Server

# keywords that tag each capability combination in the lookup table
POOL = [
    "fetch",
    "browser",
    "search",
    "postgres",
    "filesystem",
    "notion",
    "smtp",
    "webhook",
    "gmail",
    "slack",
    "shell",
    "github",
    "memory",
    "calc",
    "clock",
    "notes-app",
]


def make(name: str, source: str = "a.json") -> Server:
    return Server(name=name, client="t", source=Path(source), command="node")


def best(servers):
    (options,) = trifecta_fixes(servers).values()
    return options


def test_no_trifecta_no_fixes():
    assert trifecta_fixes([make("search"), make("postgres")]) == {}
    assert trifecta_fixes([make("calc")]) == {}


def test_one_server_per_layer_offers_all_three_equal_fixes():
    options = best([make("search"), make("postgres"), make("smtp")])
    assert [len(o.servers) for o in options] == [1, 1, 1]
    sink = next(o for o in options if o.layers == (Capability.SINK,))
    assert sink.servers == ("t:smtp",) and sink.movable
    assert "only server here that sends data out" in sink.describe()
    assert "nothing in this config can send data out" in sink.describe()


def test_choice_follows_the_layer_with_fewest_servers():
    # two sources and two sinks but one private reader: take out the private reader
    servers = [make("fetch"), make("search"), make("postgres"), make("smtp"), make("webhook")]
    top = best(servers)[0]
    assert top.servers == ("t:postgres",) and top.layers == (Capability.PRIVATE_DATA,)


def test_server_that_is_a_trifecta_alone_cannot_just_be_moved():
    top = best([make("gmail")])[0]
    assert not top.movable and top.servers == ("t:gmail",)
    text = top.describe()
    assert "moving it does not help" in text and "restrict its tools" in text


def test_a_multi_capability_server_that_is_not_a_trifecta_alone_is_movable():
    # fetch is source+sink; moving it away from postgres leaves no source and no sink here
    options = best([make("fetch"), make("postgres")])
    assert all(o.movable for o in options)
    assert options[0].servers == ("t:postgres",) or options[0].servers == ("t:fetch",)


def test_identical_server_sets_are_merged_into_one_option():
    options = best([make("fetch"), make("postgres")])
    fetch_option = next(o for o in options if o.servers == ("t:fetch",))
    assert set(fetch_option.layers) == {Capability.UNTRUSTED_SOURCE, Capability.SINK}
    assert len(options) == 2


def test_ties_prefer_movable_then_gentler_options():
    options = best([make("search"), make("postgres"), make("smtp")])
    sizes = [len(o.servers) for o in options]
    assert sizes == sorted(sizes)


def test_plural_wording_and_name_formatter():
    servers = [make("fetch"), make("search"), make("postgres"), make("smtp")]
    top = best(servers)[0]  # postgres is the only private reader here
    assert top.servers == ("t:postgres",)
    two_sinks = [make("search"), make("postgres"), make("smtp"), make("webhook"), make("fetch")]
    two = next(o for o in best(two_sinks) if len(o.servers) == 2)
    text = two.describe(lambda s: f"<{s}>")
    assert text.startswith("Move <") and "They are the only servers here" in text


def test_scopes_are_independent():
    servers = [
        make("search", "a.json"),
        make("postgres", "a.json"),
        make("smtp", "a.json"),
        make("search", "b.json"),
        make("postgres", "b.json"),
    ]
    assert list(trifecta_fixes(servers)) == ["a.json"]


def test_layers_of_reports_the_keyword():
    assert layers_of([make("fetch")])[Capability.SINK] == {"t:fetch": "fetch"}


def brute_force_minimum(servers: list[Server]) -> int:
    for size in range(1, len(servers) + 1):
        for combo in itertools.combinations(servers, size):
            gone = {s.id for s in combo}
            if not has_trifecta([s for s in servers if s.id not in gone]):
                return size
    raise AssertionError("a trifecta can always be broken by removing everything")


def test_best_option_is_exactly_the_minimum_found_by_brute_force():
    rng = random.Random(42)
    checked = 0
    for _ in range(400):
        names = rng.sample(POOL, rng.randint(2, 8))
        servers = [make(n) for n in names]
        if not has_trifecta(servers):
            continue
        checked += 1
        options = best(servers)
        assert len(options[0].servers) == brute_force_minimum(servers), names
        # and every option really does break the trifecta
        for option in options:
            rest = [s for s in servers if s.id not in option.servers]
            assert not has_trifecta(rest), (names, option)
    assert checked > 100


def test_has_trifecta_agrees_with_the_graph_analysis():
    rng = random.Random(7)
    for _ in range(300):
        servers = [make(n) for n in rng.sample(POOL, rng.randint(1, 8))]
        assert has_trifecta(servers) == bool(find_trifectas(servers)), [s.name for s in servers]


def test_movable_flag_is_accurate():
    rng = random.Random(3)
    for _ in range(300):
        servers = [make(n) for n in rng.sample(POOL, rng.randint(2, 7))]
        if not has_trifecta(servers):
            continue
        for option in best(servers):
            moved = [s for s in servers if s.id in option.servers]
            assert option.movable == (not has_trifecta(moved))


def test_fixoption_is_immutable():
    option = FixOption((Capability.SINK,), ("a",), ("a",), True, 1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        option.movable = False  # type: ignore[misc]
