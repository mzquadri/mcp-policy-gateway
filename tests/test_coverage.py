"""The coverage map has to stay true as the control set changes.

A table of "which published attack vectors does this gateway address" is the kind of
document that is correct on the day it is written and quietly wrong six months later. So
it is data rather than prose, and these tests hold it to the taxonomy it claims to follow
and to the controls that actually exist.
"""

from __future__ import annotations

import pytest
from evaluation.coverage import VECTORS, Verdict, surfaces

from mcp_policy_gateway.engine import default_controls


def control_names() -> set[str]:
    return {c.name for c in default_controls(schemas={})}


def test_every_vector_in_the_published_taxonomy_is_classified() -> None:
    # MCPSecBench (arXiv:2508.13220) enumerates 17 attack types over four surfaces.
    assert len(VECTORS) == 17


def test_the_four_surfaces_match_the_paper() -> None:
    assert surfaces() == {
        "User Interaction": 3,
        "MCP Client/Endpoint": 3,
        "MCP Transport": 2,
        "MCP Server": 9,
    }


def test_every_control_named_in_the_map_actually_exists() -> None:
    # A map citing a control that was renamed or removed is worse than no map.
    named = {name for vector in VECTORS for name in vector.controls}
    assert named <= control_names(), named - control_names()


def test_every_control_appears_somewhere_in_the_map() -> None:
    # The other direction: a new control must be placed against the taxonomy rather
    # than silently existing outside it.
    named = {name for vector in VECTORS for name in vector.controls}
    assert control_names() <= named, control_names() - named


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v.name)
def test_a_covered_vector_names_the_controls_that_cover_it(vector) -> None:
    if vector.verdict is Verdict.COVERED:
        assert vector.controls, f"{vector.name} claims coverage with no control"
    else:
        assert not vector.controls, f"{vector.name} is not covered but names controls"


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v.name)
def test_every_vector_explains_itself(vector) -> None:
    # The uncovered rows are the useful ones, so none of them may be a bare verdict.
    assert len(vector.rationale) > 40, vector.name


def test_out_of_scope_rows_say_why_the_position_cannot_see_them() -> None:
    # "Out of scope" is a claim about where the gateway sits, not an excuse, so each
    # one has to name the reason it is structural.
    structural = [v for v in VECTORS if v.verdict is Verdict.OUT_OF_SCOPE]
    assert structural, "expected some vectors to be unreachable from this position"
    for vector in structural:
        assert vector.rationale.strip().endswith("."), vector.name


def test_the_written_section_carries_the_current_table() -> None:
    # The doc quotes the map. If the map changes and the doc does not, the published
    # version is wrong in exactly the way this repository objects to elsewhere.
    from pathlib import Path

    from evaluation.coverage import table

    doc = Path(__file__).resolve().parents[1] / "docs" / "learning" / "09_coverage.md"
    assert table() in doc.read_text(encoding="utf-8")
