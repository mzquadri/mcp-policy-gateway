"""Regenerates everything in `assets/` from a live run.

These files are the ones other things quote: the README table, and the case study on
mzquadri.de. Writing them by hand is how a portfolio ends up making claims the code no
longer supports, so they are generated, committed, and regenerable with one command.

    python evaluation/make_evidence.py

Produces:
    assets/results.json        benchmark results, all three configurations, per case
    assets/control-table.json  per-control effectiveness, sorted
    assets/demo-trace.jsonl    a real trace from the hostile-server demo
    assets/summary.json        the handful of headline numbers, so a consumer does not
                               have to recompute them and risk disagreeing
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from corpus import all_cases  # noqa: E402
from evaluation.benchmark import (  # noqa: E402
    configurations,
    control_effectiveness,
    run,
)

ASSETS = ROOT / "assets"


def _git(*args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()
    except Exception:
        return "unknown"


async def _demo_trace(path: Path) -> None:
    """Drive the hostile server through the gateway and keep the trace."""
    from mcp_policy_gateway.cli import DEMO_CONTEXT
    from mcp_policy_gateway.engine import default_controls
    from mcp_policy_gateway.gateway import GatewayConfig, PolicyGateway
    from mcp_policy_gateway.trace import TraceWriter

    sandbox = Path(DEMO_CONTEXT.sandbox_root or ".")
    sandbox.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)

    config = GatewayConfig(
        command=sys.executable,
        args=[str(ROOT / "examples" / "hostile_server.py")],
        server_name="hostile-archive",
        context=DEMO_CONTEXT,
    )
    with TraceWriter(path=path, session="evidence") as trace:
        async with PolicyGateway(config, default_controls(), trace=trace) as gateway:
            await gateway.list_tools()
            for name, arguments in (
                ("list_documents", {}),
                ("search", {"query": "quarterly revenue"}),
                ("read_document", {"path": "reports/q3.txt"}),
                ("read_document", {"path": "../../../../etc/passwd"}),
                ("delete_document", {"path": "reports/q3.txt"}),
            ):
                await gateway.call_tool(name, arguments)


def main() -> int:
    ASSETS.mkdir(exist_ok=True)
    cases = all_cases()
    sandbox = ROOT / "examples" / "archive"
    sandbox.mkdir(parents=True, exist_ok=True)

    reports = {
        name: run(name, controls, cases, str(sandbox))
        for name, controls in configurations(str(sandbox)).items()
    }
    table = control_effectiveness(reports["gateway"])

    results = {
        "generated_from_commit": _git("rev-parse", "--short", "HEAD"),
        "corpus": {
            "attacks": sum(c.is_attack for c in cases),
            "benign": sum(not c.is_attack for c in cases),
            "attack_classes": sorted({c.attack_class for c in cases if c.attack_class}),
        },
        "configurations": {
            name: {
                "caught": round(report.caught, 4),
                "false_block": round(report.false_block, 4),
                "clean": round(report.clean, 4),
                "median_micros": report.median_micros,
                "outcomes": [asdict(o) for o in report.outcomes],
            }
            for name, report in reports.items()
        },
    }
    (ASSETS / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    (ASSETS / "control-table.json").write_text(
        json.dumps(
            [
                {"control": control, **row}
                for control, row in sorted(table.items(), key=lambda kv: -kv[1]["attacks_caught"])
            ],
            indent=2,
        ),
        encoding="utf-8",
    )

    asyncio.run(_demo_trace(ASSETS / "demo-trace.jsonl"))

    gateway, keyword, baseline = reports["gateway"], reports["keyword"], reports["baseline"]
    unhandled = sorted(o.case_id for o in gateway.outcomes if not o.ok)
    summary = {
        "corpus_cases": len(cases),
        "attacks": results["corpus"]["attacks"],
        "benign": results["corpus"]["benign"],
        "attack_classes": len(results["corpus"]["attack_classes"]),
        "gateway_caught": round(gateway.caught, 4),
        "gateway_false_block": round(gateway.false_block, 4),
        "keyword_caught": round(keyword.caught, 4),
        "keyword_false_block": round(keyword.false_block, 4),
        "baseline_caught": round(baseline.caught, 4),
        "median_micros": gateway.median_micros,
        "controls": len(table),
        "unhandled": unhandled,
    }
    (ASSETS / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    for key, value in summary.items():
        print(f"{key:<24}{value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
