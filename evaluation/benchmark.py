"""Scores the gateway against the corpus, and against doing nothing.

The comparison that matters is not "does the gateway catch things" - of course it does,
it was written against this corpus. It is:

    baseline     no gateway. Every call proceeds. This is what an MCP client does today.
    keyword      a strawman that any team would write first: match the obvious phrases,
                 no context, no shape. Included because "we added a filter" is the real
                 alternative to this project, not "we added nothing", and a comparison
                 against nothing flatters the result.
    gateway      the full control set.

Three numbers per configuration:

    caught       share of attack cases where the response was at least what the case
                 requires. Recall.
    false block  share of benign cases refused outright. The number that decides whether
                 the thing is deployable, and the one the keyword baseline loses on.
    clean        share of benign cases passed with no action at all.

Per-control effectiveness is reported by attributing each caught attack to the controls
that fired on it. A case can be caught by more than one control, and that is not
double-counting - it is defence in depth, and the table says how much of it there is.

Everything here is deterministic. No model is called, no network is touched, and the
same corpus produces the same table on any machine. That is a deliberate constraint:
an evaluation that needs an API key is an evaluation nobody re-runs.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from corpus import Case, all_cases  # noqa: E402

from mcp_policy_gateway.controls.base import Context, Control, Event  # noqa: E402
from mcp_policy_gateway.engine import PolicyEngine, default_controls  # noqa: E402
from mcp_policy_gateway.types import (  # noqa: E402
    Action,
    Decision,
    Finding,
    Severity,
    Stage,
    ToolCall,
    ToolDeclaration,
    ToolResult,
)

#: The deployment the corpus is written against.
DEFAULT_ALLOWED_TOOLS = frozenset(
    {"read_document", "search", "summarise", "fetch_url", "post_message", "delete_document"}
)
DEFAULT_DESTRUCTIVE = frozenset({"delete_document"})
DEFAULT_HOSTS = frozenset({"docs.internal.example.com", "example.com"})
DEFAULT_SCHEMAS: dict[str, dict[str, Any]] = {
    "read_document": {
        "type": "object",
        "properties": {"path": {"type": "string"}, "encoding": {"type": "string"}},
        "required": ["path"],
        "additionalProperties": False,
    },
    "delete_document": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
        "additionalProperties": False,
    },
    "fetch_url": {
        "type": "object",
        "properties": {"url": {"type": "string"}},
        "required": ["url"],
        "additionalProperties": False,
    },
}


class KeywordFilter:
    """The strawman: substring matching with no notion of shape or context.

    This is not a straw man in the pejorative sense - it is what gets written first,
    and it is genuinely effective at recall. It is here to show what it costs.
    """

    name = "keyword_filter"
    stages = frozenset({Stage.DISCOVERY, Stage.RESPONSE, Stage.REQUEST})
    PHRASES = (
        "ignore all previous instructions",
        "ignore previous instructions",
        "disregard",
        "system prompt",
        "do not tell",
        "new instructions",
        "..",
        "api_key",
        "password",
    )

    def inspect(self, event: Event, context: Context) -> Iterable[Finding]:
        haystack = event.text
        if event.call is not None:
            haystack = "\n".join(f"{k}={v}" for k, v in event.call.arguments.items())
        low = haystack.lower()
        for phrase in self.PHRASES:
            index = low.find(phrase)
            if index >= 0:
                yield Finding(
                    control=self.name,
                    rule=phrase.replace(" ", "_"),
                    action=Action.BLOCK,
                    severity=Severity.MEDIUM,
                    detail=f"Matched {phrase!r}.",
                    span=(index, index + len(phrase)),
                )


def build_context(case: Case, sandbox: str) -> Context:
    context = Context(
        sandbox_root=sandbox,
        allowed_tools=DEFAULT_ALLOWED_TOOLS,
        destructive_tools=DEFAULT_DESTRUCTIVE,
        allowed_hosts=DEFAULT_HOSTS,
        claimed_tools={},
    )
    for key, value in case.context.items():
        setattr(context, key, dict(value) if isinstance(value, dict) else value)
    return context


def build_event(case: Case) -> Event:
    if case.stage is Stage.DISCOVERY:
        return Event(
            stage=case.stage,
            declaration=ToolDeclaration(
                server=case.server,
                name=case.tool,
                description=case.description,
                input_schema=DEFAULT_SCHEMAS.get(case.tool, {}),
            ),
        )
    if case.stage is Stage.REQUEST:
        return Event(
            stage=case.stage,
            call=ToolCall(server=case.server, tool=case.tool, arguments=case.arguments),
        )
    return Event(
        stage=case.stage,
        result=ToolResult(text=case.text, is_error=case.is_error),
        origin=ToolCall(server=case.server, tool=case.tool, arguments=case.arguments),
    )


def handled(case: Case, decision: Decision) -> bool:
    """Did the response meet what this case requires?"""
    if case.is_attack:
        return decision.action.severity >= case.expected.severity
    return decision.action.severity <= case.expected.severity


@dataclass(slots=True)
class Outcome:
    case_id: str
    label: str
    attack_class: str | None
    action: str
    expected: str
    ok: bool
    rules: list[str] = field(default_factory=list)
    micros: float = 0.0


#: 95%, two-sided.
Z = 1.959963984540054


def wilson(successes: int, total: int, z: float = Z) -> tuple[float, float]:
    """A 95% interval for a proportion, by the Wilson score method.

    Every rate in this table is a count over 26 attacks or 21 benign cases, and a
    rate from twenty-odd cases carries an interval wide enough to change what may
    be claimed from it. Printing 96.2% alone invites the reader to treat it as
    precise, which at n=26 it is not.

    Wilson rather than the textbook normal approximation, because the approximation
    fails exactly where this corpus sits. At 25 of 26 it puts the upper bound past
    1, which is not a probability, and at 0 of 21 it collapses to the single point
    zero, claiming no uncertainty at all from twenty-one observations. Wilson stays
    inside [0, 1] at every count and keeps a sensible width at the ends.

    This covers sampling error only. It answers how much the number would move on
    another 26 cases drawn the same way, not how the gateway would do on real
    traffic, which no corpus of this size can answer.
    """
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    denominator = 1 + z**2 / total
    centre = (p + z**2 / (2 * total)) / denominator
    spread = z * ((p * (1 - p) / total + z**2 / (4 * total**2)) ** 0.5) / denominator
    return (max(0.0, centre - spread), min(1.0, centre + spread))


@dataclass(slots=True)
class Report:
    configuration: str
    outcomes: list[Outcome]

    def _subset(self, label: str) -> list[Outcome]:
        return [o for o in self.outcomes if o.label == label]

    @property
    def caught_count(self) -> tuple[int, int]:
        attacks = self._subset("attack")
        return sum(o.ok for o in attacks), len(attacks)

    @property
    def false_block_count(self) -> tuple[int, int]:
        benign = self._subset("benign")
        return sum(o.action == Action.BLOCK.value for o in benign), len(benign)

    @property
    def clean_count(self) -> tuple[int, int]:
        benign = self._subset("benign")
        return sum(o.action == Action.ALLOW.value for o in benign), len(benign)

    @property
    def caught(self) -> float:
        successes, total = self.caught_count
        return successes / total if total else 0.0

    @property
    def false_block(self) -> float:
        successes, total = self.false_block_count
        return successes / total if total else 0.0

    @property
    def clean(self) -> float:
        successes, total = self.clean_count
        return successes / total if total else 0.0

    def interval(self, which: str) -> tuple[float, float]:
        """The 95% Wilson interval for one of the three rates."""
        return wilson(*getattr(self, f"{which}_count"))

    @property
    def median_micros(self) -> float:
        values = sorted(o.micros for o in self.outcomes)
        return values[len(values) // 2] if values else 0.0


def run(
    configuration: str, controls: Sequence[Control], cases: Sequence[Case], sandbox: str
) -> Report:
    outcomes: list[Outcome] = []
    for case in cases:
        # Rebuilt per case so stateful controls cannot leak counts between cases. The
        # budget control is the only one affected, and its cases are self-contained.
        engine = PolicyEngine(controls=list(controls))
        context = build_context(case, sandbox)
        event = build_event(case)

        started = time.perf_counter()
        decision = engine.evaluate(event, context)
        micros = (time.perf_counter() - started) * 1e6

        outcomes.append(
            Outcome(
                case_id=case.case_id,
                label=case.label,
                attack_class=case.attack_class,
                action=decision.action.value,
                expected=case.expected.value,
                ok=handled(case, decision),
                rules=decision.rules,
                micros=round(micros, 1),
            )
        )
    return Report(configuration=configuration, outcomes=outcomes)


def control_effectiveness(report: Report) -> dict[str, dict[str, int]]:
    """Which control fired on which caught attack, and on which benign refusal."""
    table: dict[str, dict[str, int]] = {}
    for outcome in report.outcomes:
        for rule in outcome.rules:
            control = rule.split(":", 1)[0]
            row = table.setdefault(control, {"attacks_caught": 0, "benign_touched": 0})
            if outcome.label == "attack" and outcome.ok:
                row["attacks_caught"] += 1
            elif outcome.label == "benign":
                row["benign_touched"] += 1
    return table


def configurations(sandbox: str) -> dict[str, list[Control]]:
    return {
        "baseline": [],
        "keyword": [KeywordFilter()],
        "gateway": default_controls(schemas=DEFAULT_SCHEMAS),
    }


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Score the gateway against the corpus.")
    parser.add_argument("--json", type=Path, help="write the full result set here")
    parser.add_argument("--fast", action="store_true", help="skip the oversized-payload case")
    args = parser.parse_args(argv)

    sandbox = str(ROOT / "examples" / "archive")
    Path(sandbox).mkdir(parents=True, exist_ok=True)

    cases = all_cases()
    if args.fast:
        cases = [c for c in cases if len(c.text) < 50_000]

    reports = {
        name: run(name, controls, cases, sandbox)
        for name, controls in configurations(sandbox).items()
    }

    attacks = sum(c.label == "attack" for c in cases)
    benign = len(cases) - attacks
    print(f"corpus: {attacks} attack cases, {benign} benign cases\n")
    print(f"{'configuration':<14}{'caught':>9}{'false block':>14}{'clean pass':>13}{'median':>10}")
    for name, report in reports.items():
        print(
            f"{name:<14}{report.caught:>8.1%}{report.false_block:>14.1%}"
            f"{report.clean:>13.1%}{report.median_micros:>9.0f}us"
        )

    # Printed under the table rather than beside each rate, because three intervals
    # on one line is unreadable and the widths are the point: at these counts they
    # are wide enough that the ranking, not the gap, is what the corpus supports.
    print("\n95% Wilson intervals, sampling error only")
    print(f"{'configuration':<14}{'caught':>20}{'false block':>20}")
    for name, report in reports.items():
        low_c, high_c = report.interval("caught")
        low_f, high_f = report.interval("false_block")
        print(f"{name:<14}{f'[{low_c:.1%}, {high_c:.1%}]':>20}{f'[{low_f:.1%}, {high_f:.1%}]':>20}")

    print("\nper-control, gateway configuration")
    print(f"{'control':<26}{'attacks caught':>16}{'benign touched':>16}")
    for control, row in sorted(
        control_effectiveness(reports["gateway"]).items(),
        key=lambda kv: -kv[1]["attacks_caught"],
    ):
        print(f"{control:<26}{row['attacks_caught']:>16}{row['benign_touched']:>16}")

    misses = [o for o in reports["gateway"].outcomes if not o.ok]
    print(f"\nunhandled by the gateway: {len(misses)}")
    for outcome in misses:
        print(
            f"  {outcome.case_id:<20}{outcome.label:<9}"
            f"got {outcome.action:<18}want {outcome.expected}"
        )

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "corpus": {"attacks": attacks, "benign": benign},
            "configurations": {
                name: {
                    "caught": report.caught,
                    "false_block": report.false_block,
                    "clean": report.clean,
                    "median_micros": report.median_micros,
                    "outcomes": [asdict(o) for o in report.outcomes],
                }
                for name, report in reports.items()
            },
            "control_effectiveness": control_effectiveness(reports["gateway"]),
        }
        args.json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
