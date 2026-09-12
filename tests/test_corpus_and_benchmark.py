"""The corpus is data, so it gets tested like data, and the headline numbers are pinned.

Two jobs here. The first is corpus hygiene: unique ids, coherent ground truth, and a
benign half that is actually adversarial rather than filler. The second is that the
numbers in the README cannot drift silently - if a control changes and the benchmark
moves, a test fails and the README has to be updated deliberately.

The pinned bounds are ranges rather than exact equalities. An exact pin turns every
improvement into a test failure and trains people to update the number without reading
it. A range fails when something has genuinely regressed.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from corpus import all_cases
from evaluation.benchmark import (
    DEFAULT_SCHEMAS,
    configurations,
    control_effectiveness,
    handled,
    run,
)

from mcp_policy_gateway.engine import default_controls
from mcp_policy_gateway.types import Action, Stage

CASES = all_cases()


# ------------------------------------------------------------------ hygiene


def test_case_ids_are_unique():
    ids = [c.case_id for c in CASES]
    assert len(ids) == len(set(ids))


def test_corpus_has_both_halves_in_useful_proportion():
    attacks = [c for c in CASES if c.is_attack]
    benign = [c for c in CASES if not c.is_attack]
    assert len(attacks) >= 20
    # A benign half this size is what makes the false-positive rate meaningful.
    assert len(benign) >= 15


def test_every_case_explains_itself():
    for case in CASES:
        assert len(case.rationale) > 40, f"{case.case_id} needs a real rationale"


def test_attacks_declare_an_attack_class_and_benign_do_not():
    for case in CASES:
        if case.is_attack:
            assert case.attack_class, case.case_id
        else:
            assert case.attack_class is None, case.case_id


def test_attack_expectations_are_at_least_sanitise():
    """An attack whose ground truth is ALLOW would be scored as handled by doing nothing."""
    for case in CASES:
        if case.is_attack:
            assert case.expected.severity >= Action.SANITISE.severity, case.case_id


def test_benign_expectations_never_permit_a_block():
    for case in CASES:
        if not case.is_attack:
            assert case.expected.severity < Action.BLOCK.severity, case.case_id


def test_attack_classes_cover_the_stages_that_matter():
    stages = {c.stage for c in CASES if c.is_attack}
    assert stages == {Stage.DISCOVERY, Stage.REQUEST, Stage.RESPONSE}


def test_corpus_spans_at_least_eight_attack_classes():
    classes = {c.attack_class for c in CASES if c.is_attack}
    assert len(classes) >= 8, sorted(classes)


# ------------------------------------------------------------------ results


@pytest.fixture(scope="module")
def reports(tmp_path_factory):
    sandbox = tmp_path_factory.mktemp("archive")
    return {
        name: run(name, controls, CASES, str(sandbox))
        for name, controls in configurations(str(sandbox)).items()
    }


def test_baseline_catches_nothing_and_breaks_nothing(reports):
    baseline = reports["baseline"]
    assert baseline.caught == 0.0
    assert baseline.false_block == 0.0


def test_keyword_filter_trades_badly(reports):
    """The point of including it: high refusal rate on legitimate traffic."""
    keyword = reports["keyword"]
    assert keyword.caught < 0.6
    assert keyword.false_block > 0.25


def test_gateway_beats_both_on_both_axes(reports):
    gateway, keyword = reports["gateway"], reports["keyword"]
    assert gateway.caught > keyword.caught
    assert gateway.false_block < keyword.false_block


def test_gateway_headline_numbers_hold(reports):
    """Pinned as ranges so a real regression fails and an improvement does not."""
    gateway = reports["gateway"]
    assert 0.88 <= gateway.caught <= 1.0, gateway.caught
    assert gateway.false_block <= 0.15, gateway.false_block


def test_the_only_unhandled_cases_are_the_documented_ones(reports):
    """A new miss should fail here rather than quietly lower the headline number."""
    unhandled = {o.case_id for o in reports["gateway"].outcomes if not o.ok}
    assert unhandled == {"inject-006", "secret-004", "fp-known-001", "fp-known-002"}


def test_deterministic_controls_have_no_false_positives(reports):
    """Only the one control allowed to be uncertain may touch a benign case."""
    table = control_effectiveness(reports["gateway"])
    for control, row in table.items():
        if control == "instruction_injection":
            continue
        assert row["benign_touched"] == 0, f"{control} touched benign traffic"


def test_benchmark_is_reproducible(tmp_path):
    """Same corpus, same controls, same answer - twice."""
    first = run("gateway", default_controls(schemas=DEFAULT_SCHEMAS), CASES, str(tmp_path))
    second = run("gateway", default_controls(schemas=DEFAULT_SCHEMAS), CASES, str(tmp_path))
    assert [o.action for o in first.outcomes] == [o.action for o in second.outcomes]
    assert first.caught == second.caught


def test_every_attack_class_is_caught_at_least_once(reports):
    caught_classes = {
        o.attack_class for o in reports["gateway"].outcomes if o.label == "attack" and o.ok
    }
    all_classes = {c.attack_class for c in CASES if c.is_attack}
    missing = all_classes - caught_classes
    assert not missing, f"no case caught for {missing}"


def test_handled_semantics_are_asymmetric():
    """Attacks need at least the expected action; benign need at most it."""
    from mcp_policy_gateway.types import Decision

    attack = next(c for c in CASES if c.is_attack and c.expected is Action.BLOCK)
    benign = next(c for c in CASES if not c.is_attack and c.expected is Action.ALLOW)
    assert handled(attack, Decision(action=Action.BLOCK))
    assert not handled(attack, Decision(action=Action.SANITISE))
    assert handled(benign, Decision(action=Action.ALLOW))
    assert not handled(benign, Decision(action=Action.BLOCK))


# ------------------------------------------------------------------ the README

# The pinned bounds above are ranges on purpose, for the reason in the module
# docstring. This is a different question and takes the opposite answer.
#
# The README prints a rate table and says the benchmark "reproduces every rate in
# this table exactly on any machine". That is a claim about two published
# artifacts agreeing, not a quality floor. An improvement to a control SHOULD
# fail this test: the README is wrong the moment the benchmark moves, and both
# belong in the same commit.
#
# The decision-time column is excluded. It is a property of the machine, which
# the README says in the sentence above the table, and it differs between a
# laptop and a CI runner by tens of microseconds.

README = Path(__file__).resolve().parents[1] / "README.md"

# The label the README gives each configuration, mapped to the name the
# benchmark uses. Matching on a substring keeps the bold markers and the
# parenthetical out of it.
ROW_LABELS = {
    "baseline": "baseline",
    "keyword filter": "keyword",
    "gateway": "gateway",
}


def readme_rate_table() -> dict[str, tuple[str, str, str]]:
    """The three rate columns of the README table, keyed by configuration."""
    table: dict[str, tuple[str, str, str]] = {}
    for line in README.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|") or "%" not in line:
            continue
        cells = [c.strip().strip("*").strip() for c in line.strip("|").split("|")]
        if len(cells) < 4:
            continue
        # "gateway" is a substring of nothing else here, but "baseline" arrives
        # as "baseline (no gateway)", so the longest match wins.
        label = cells[0].lower()
        matched = sorted((key for key in ROW_LABELS if key in label), key=len, reverse=True)
        if matched:
            table[ROW_LABELS[matched[0]]] = (cells[1], cells[2], cells[3])
    return table


def test_the_readme_table_is_the_benchmark(reports):
    table = readme_rate_table()
    assert set(table) == set(reports), (
        f"README table lists {sorted(table)}, benchmark runs {sorted(reports)}"
    )

    for name, report in reports.items():
        caught, refused, untouched = table[name]
        assert caught == f"{report.caught * 100:.1f}%", (
            f"{name} attacks caught: README says {caught}, benchmark says "
            f"{report.caught * 100:.1f}%"
        )
        assert refused == f"{report.false_block * 100:.1f}%", (
            f"{name} benign refused: README says {refused}, benchmark says "
            f"{report.false_block * 100:.1f}%"
        )
        assert untouched == f"{report.clean * 100:.1f}%", (
            f"{name} benign untouched: README says {untouched}, benchmark says "
            f"{report.clean * 100:.1f}%"
        )


def test_the_readme_states_the_corpus_size_it_was_run_on():
    text = README.read_text(encoding="utf-8")
    attacks = [c for c in CASES if c.is_attack]
    benign = [c for c in CASES if not c.is_attack]
    assert f"{len(CASES)} cases" in text, f"README does not state {len(CASES)} cases"
    assert f"{len(attacks)} attack" in text, (
        f"README does not state the {len(attacks)} attack cases"
    )
    assert f"{len(benign)} benign" in text, f"README does not state the {len(benign)} benign cases"
