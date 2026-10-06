"""Score the gateway against an external corpus.

    python -m evaluation.external              # fetch if needed, score, print
    python -m evaluation.external --json out.json

Unlike `evaluation/benchmark.py` this touches the network on first run, which is why it
lives behind its own entry point and its own make target. Once the cache is warm it is
offline and deterministic like everything else.

The output deliberately leads with provenance and ends with the caveats, because the
number in the middle means nothing without either.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for path in (str(ROOT / "src"), str(ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

from evaluation.benchmark import wilson  # noqa: E402
from evaluation.external.adapt import mcptox_cases  # noqa: E402
from evaluation.external.fetch import ExternalCorpusError, load  # noqa: E402
from evaluation.external.score import ExternalReport, score  # noqa: E402
from evaluation.external.sources import MCPTOX  # noqa: E402

SANDBOX = "/srv/sandbox"


def pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def emit(result: ExternalReport) -> None:
    source = MCPTOX
    print(f"source      {source.name}")
    print(f"commit      {source.ref}")
    print(f"sha256      {source.sha256}")
    print(f"citation    {source.citation}")
    print(f"licence     {source.licence}")
    print()

    low, high = result.interval
    print(f"{result.total} poisoned tool declarations, scored at the discovery stage")
    print()
    print(f"caught      {result.caught}/{result.total}  {pct(result.recall)}")
    print(f"95% Wilson  [{pct(low)}, {pct(high)}]")
    print()

    print("by generator (their `paradigm`)")
    for name, (caught, total) in result.by_paradigm.items():
        lo, hi = wilson(caught, total)
        print(
            f"  {name:<14} {caught:>4}/{total:<4} {pct(caught / total):>7}   [{pct(lo)}, {pct(hi)}]"
        )
    print()

    print("by risk category (their `security risk`)")
    for name, (caught, total) in result.by_security_risk.items():
        print(f"  {name:<24} {caught:>4}/{total:<4} {pct(caught / total):>7}")
    print()

    controls = result.controls()
    print("controls that fired on a caught declaration")
    if controls:
        for name, count in controls.items():
            print(f"  {name:<24} {count}")
    else:
        print("  none")
    print()

    missed = result.missed()
    print(f"not handled: {len(missed)}")
    for outcome in missed[:5]:
        print(f"  {outcome.case_id:<28} got {outcome.action:<10} want {outcome.expected}")
    if len(missed) > 5:
        print(f"  ... and {len(missed) - 5} more")
    print()

    print("Reading this number")
    print("  Only tool_shadowing and instruction_injection run at the discovery stage, so")
    print("  this scores those two controls, not the nine-control gateway.")
    print("  MCPTox scores whether a model complies; this scores whether a control fires.")
    print("  These rates are a reinterpretation of their labels and are NOT comparable to")
    print("  the attack success rates in their paper.")
    print("  All cases come from three generators, so the pooled interval overstates the")
    print("  independence of the evidence. Read the per-generator rows first.")


def main() -> int:
    parser = argparse.ArgumentParser(prog="evaluation.external")
    parser.add_argument("--json", type=Path, default=None, help="write the run as JSON")
    args = parser.parse_args()

    try:
        body = load(MCPTOX)
    except ExternalCorpusError as exc:
        print(f"external corpus unavailable: {exc}", file=sys.stderr)
        return 2

    externals = mcptox_cases(json.loads(body))
    result = score(externals, sandbox=SANDBOX)
    emit(result)

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(
                {
                    "source": {
                        "name": MCPTOX.name,
                        "ref": MCPTOX.ref,
                        "sha256": MCPTOX.sha256,
                        "citation": MCPTOX.citation,
                        "licence": MCPTOX.licence,
                    },
                    "total": result.total,
                    "caught": result.caught,
                    "recall": result.recall,
                    "interval": list(result.interval),
                    "by_paradigm": {k: list(v) for k, v in result.by_paradigm.items()},
                    "by_security_risk": {k: list(v) for k, v in result.by_security_risk.items()},
                    "controls": result.controls(),
                    "missed": [o.case_id for o in result.missed()],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
