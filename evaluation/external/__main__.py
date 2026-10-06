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

from evaluation.benchmark import DEFAULT_SCHEMAS, Report, run, wilson  # noqa: E402
from evaluation.external.adapt import mcptox_cases  # noqa: E402
from evaluation.external.fetch import ExternalCorpusError, load  # noqa: E402
from evaluation.external.harvest import (  # noqa: E402
    benign_cases,
    declarations,
    mcpguard_benign,
)
from evaluation.external.score import ExternalReport, score  # noqa: E402
from evaluation.external.sources import (  # noqa: E402
    MCPGUARD_DEV,
    MCPTOX,
    REFERENCE_SERVERS,
)

from mcp_policy_gateway.engine import default_controls  # noqa: E402

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


def benign() -> tuple[Report, dict[str, int]]:
    """Score real declarations: the reference servers, plus MCP-Guard's benign half."""
    cases = []
    per_source: dict[str, int] = {}
    for server, language, source in REFERENCE_SERVERS:
        found = declarations(load(source).decode("utf-8", errors="replace"), language=language)
        per_source[server] = len(found)
        cases.extend(benign_cases(found, server=server))

    guard = mcpguard_benign(load(MCPGUARD_DEV).decode("utf-8", errors="replace"))
    per_source["mcpguard (benign half)"] = len(guard)
    cases.extend(guard)

    report = run("gateway", default_controls(schemas=DEFAULT_SCHEMAS), cases, SANDBOX)
    return report, per_source


def emit_benign(report: Report, per_server: dict[str, int]) -> None:
    total = len(report.outcomes)
    print()
    print("=" * 72)
    print(f"{total} real tool declarations, from sources nobody wrote to be tested")
    print()
    print("harvested per source")
    for server, count in per_server.items():
        note = "   <- none found; format may have changed" if count == 0 else ""
        print(f"  {server:<22} {count}{note}")
    print()

    blocked, n = report.false_block_count
    clean, _ = report.clean_count
    lo, hi = report.interval("false_block")
    touched = n - clean
    print(f"blocked        {blocked}/{n}  {pct(report.false_block)}  [{pct(lo)}, {pct(hi)}]")
    print(f"touched at all {touched}/{n}  {pct(touched / n) if n else '-'}")
    print()

    offenders = [o for o in report.outcomes if not o.ok]
    print(f"false positives (any action on a real tool): {len(offenders)}")
    for o in offenders:
        print(f"  {o.case_id:<44} {o.action:<10} {','.join(o.rules)}")


def main() -> int:
    parser = argparse.ArgumentParser(prog="evaluation.external")
    parser.add_argument("--json", type=Path, default=None, help="write the run as JSON")
    args = parser.parse_args()

    try:
        body = load(MCPTOX)
        benign_report, per_server = benign()
    except ExternalCorpusError as exc:
        print(f"external corpus unavailable: {exc}", file=sys.stderr)
        return 2

    externals = mcptox_cases(json.loads(body))
    result = score(externals, sandbox=SANDBOX)
    emit(result)
    emit_benign(benign_report, per_server)

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
