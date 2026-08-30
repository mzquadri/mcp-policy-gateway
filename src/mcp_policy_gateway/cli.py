"""Command line entry points.

Three commands, each answering a question someone actually asks:

    demo      does this work against a real MCP server?
    proxy     run the gateway in front of a server I already use.
    trace     what happened in that run?

`demo` launches the hostile example server as a subprocess, drives it through the
gateway, and prints the decisions. It needs no API key, no network and no configuration,
which makes it the first thing to run after cloning and the thing CI runs to prove the
protocol path still works.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .controls.base import Context
from .engine import default_controls
from .gateway import GatewayConfig, PolicyGateway
from .trace import TraceWriter, default_trace_path, read_trace

ROOT = Path(__file__).resolve().parents[2]

#: The deployment the demo runs under. Chosen to be restrictive enough to be worth
#: having and loose enough that the honest calls in the demo still succeed.
DEMO_CONTEXT = Context(
    sandbox_root=str(ROOT / "examples" / "archive"),
    allowed_tools=frozenset({"read_document", "search", "list_documents", "delete_document"}),
    destructive_tools=frozenset({"delete_document"}),
    allowed_hosts=frozenset({"docs.internal.example.com"}),
)


async def _run_demo(trace_path: Path) -> int:
    config = GatewayConfig(
        command=sys.executable,
        args=[str(ROOT / "examples" / "hostile_server.py")],
        server_name="hostile-archive",
        context=DEMO_CONTEXT,
    )
    Path(config.context.sandbox_root or ".").mkdir(parents=True, exist_ok=True)

    with TraceWriter(path=trace_path, session="demo") as trace:
        async with PolicyGateway(config, default_controls(), trace=trace) as gateway:
            tools = await gateway.list_tools()
            print("tools presented to the client after discovery policy:")
            for tool in tools:
                description = (tool.description or "").replace("\n", " ")
                print(f"  {tool.name:<18} {description[:78]}")
            hidden = set(gateway.withheld) - {t.name for t in tools}
            if hidden:
                print(f"  withheld: {', '.join(sorted(hidden))}")

            print("\ncalls:")
            for name, arguments in (
                ("list_documents", {}),
                ("search", {"query": "quarterly revenue"}),
                ("read_document", {"path": "reports/q3.txt"}),
                ("read_document", {"path": "../../../../etc/passwd"}),
                ("delete_document", {"path": "reports/q3.txt"}),
            ):
                result = await gateway.call_tool(name, arguments)
                text = ""
                for block in result.content or []:
                    text += getattr(block, "text", "")
                status = "REFUSED" if result.is_error else "allowed"
                head = text.replace("\n", " ")[:96]
                print(f"  {name:<18} {str(arguments)[:38]:<40} {status:<8} {head}")

    print(f"\ntrace written to {trace_path}")
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    return asyncio.run(_run_demo(args.trace or default_trace_path()))


def _cmd_proxy(args: argparse.Namespace) -> int:
    async def run() -> int:
        context = Context(
            sandbox_root=args.sandbox,
            allowed_tools=frozenset(args.allow or ()),
            destructive_tools=frozenset(args.destructive or ()),
            allowed_hosts=frozenset(args.allow_host or ()),
        )
        config = GatewayConfig(
            command=args.command,
            args=list(args.argv or []),
            server_name=args.name,
            context=context,
        )
        with TraceWriter(path=args.trace or default_trace_path(), session=args.name) as trace:
            async with PolicyGateway(config, default_controls(), trace=trace) as gateway:
                for tool in await gateway.list_tools():
                    print(tool.name)
        return 0

    return asyncio.run(run())


def _cmd_trace(args: argparse.Namespace) -> int:
    entries = read_trace(args.path)
    if args.json:
        print(json.dumps(entries, indent=2))
        return 0
    print(f"{'stage':<11}{'tool':<18}{'action':<18}{'us':>7}  rules")
    for entry in entries:
        rules = ", ".join(entry.get("rules") or []) or "-"
        print(
            f"{entry['stage']:<11}{entry.get('tool')!s:<18}"
            f"{entry['action']:<18}{entry.get('micros', 0):>7.0f}  {rules[:70]}"
        )
    blocked = sum(e["action"] == "block" for e in entries)
    print(f"\n{len(entries)} events, {blocked} refused")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-policy-gateway", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run the gateway against the hostile example server")
    demo.add_argument("--trace", type=Path)
    demo.set_defaults(func=_cmd_demo)

    proxy = sub.add_parser("proxy", help="front an existing MCP server")
    proxy.add_argument("command", help="the downstream server executable")
    proxy.add_argument("argv", nargs="*", help="arguments for it")
    proxy.add_argument("--name", default="downstream")
    proxy.add_argument("--sandbox")
    proxy.add_argument("--allow", action="append", help="permit a tool (repeatable)")
    proxy.add_argument("--destructive", action="append", help="needs approval (repeatable)")
    proxy.add_argument("--allow-host", action="append", help="permit a host (repeatable)")
    proxy.add_argument("--trace", type=Path)
    proxy.set_defaults(func=_cmd_proxy)

    show = sub.add_parser("trace", help="read a trace back")
    show.add_argument("path", type=Path)
    show.add_argument("--json", action="store_true")
    show.set_defaults(func=_cmd_trace)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
