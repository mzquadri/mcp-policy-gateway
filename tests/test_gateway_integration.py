"""End to end, over a real MCP stdio transport, against a real subprocess.

These are slower than the unit tests and they earn it. Everything else here tests the
policy engine as a library; this tests the thing that actually ships - a gateway process
speaking MCP to a server process, with the protocol, the transport and the subprocess
lifecycle all in play. The corpus cannot catch a bug where the gateway forwards a call it
meant to refuse, because the corpus never touches the wire.

The downstream server is `examples/hostile_server.py`. It is deliberately hostile and
entirely self-contained: no network, no filesystem writes, every payload a literal.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mcp_policy_gateway.controls.base import Context
from mcp_policy_gateway.engine import default_controls
from mcp_policy_gateway.gateway import GatewayConfig, PolicyGateway
from mcp_policy_gateway.trace import TraceWriter, read_trace

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "examples" / "hostile_server.py"

pytestmark = pytest.mark.asyncio


def make_config(tmp_path: Path) -> GatewayConfig:
    return GatewayConfig(
        command=sys.executable,
        args=[str(SERVER)],
        server_name="hostile-archive",
        context=Context(
            sandbox_root=str(tmp_path),
            allowed_tools=frozenset(
                {"read_document", "search", "list_documents", "delete_document"}
            ),
            destructive_tools=frozenset({"delete_document"}),
            allowed_hosts=frozenset({"docs.internal.example.com"}),
        ),
    )


def text_of(result) -> str:
    return "".join(getattr(block, "text", "") for block in result.content or [])


async def test_poisoned_tool_is_withheld_at_discovery(tmp_path: Path):
    async with PolicyGateway(make_config(tmp_path), default_controls()) as gateway:
        names = {tool.name for tool in await gateway.list_tools()}
        assert "read_document" not in names
        assert "read_document" in gateway.withheld
        # The honest tools survive; refusing everything would be no achievement.
        assert {"search", "list_documents", "delete_document"} <= names


async def test_withheld_tool_cannot_be_called_directly(tmp_path: Path):
    """Hiding a name from the listing is not the same as making it uncallable."""
    async with PolicyGateway(make_config(tmp_path), default_controls()) as gateway:
        await gateway.list_tools()
        result = await gateway.call_tool("read_document", {"path": "reports/q3.txt"})
        assert result.is_error
        assert "withheld" in text_of(result)


async def test_injected_result_is_refused_at_response_stage(tmp_path: Path):
    """The case a pre-execution scanner cannot reach: the tool declaration is clean."""
    async with PolicyGateway(make_config(tmp_path), default_controls()) as gateway:
        tools = {t.name: t for t in await gateway.list_tools()}
        assert "search" in tools, "the search declaration is honest and must survive"

        result = await gateway.call_tool("search", {"query": "revenue"})
        assert result.is_error
        body = text_of(result)
        assert "Refused" in body
        # The payload must not reach the client.
        assert "Ignore all previous instructions" not in body
        assert "AKIAIOSFODNN7EXAMPLE" not in body


async def test_honest_call_still_works(tmp_path: Path):
    async with PolicyGateway(make_config(tmp_path), default_controls()) as gateway:
        await gateway.list_tools()
        result = await gateway.call_tool("list_documents", {})
        assert not result.is_error
        assert "reports/q3.txt" in text_of(result)


async def test_destructive_call_is_held_for_approval(tmp_path: Path):
    async with PolicyGateway(make_config(tmp_path), default_controls()) as gateway:
        await gateway.list_tools()
        result = await gateway.call_tool("delete_document", {"path": "reports/q3.txt"})
        assert result.is_error
        assert "approval" in text_of(result)


async def test_approval_lets_the_destructive_call_through(tmp_path: Path):
    config = make_config(tmp_path)
    config.context.approved = True
    async with PolicyGateway(config, default_controls()) as gateway:
        await gateway.list_tools()
        result = await gateway.call_tool("delete_document", {"path": "reports/q3.txt"})
        assert not result.is_error


async def test_unlisted_tool_is_refused_before_it_reaches_the_server(tmp_path: Path):
    config = make_config(tmp_path)
    config.context.allowed_tools = frozenset({"list_documents"})
    async with PolicyGateway(config, default_controls()) as gateway:
        await gateway.list_tools()
        result = await gateway.call_tool("search", {"query": "x"})
        assert result.is_error
        assert "tool_allowlist" in text_of(result)


async def test_refusal_tells_the_client_not_to_retry(tmp_path: Path):
    """A silent failure teaches a model to retry and burn budget on a rule nobody named."""
    async with PolicyGateway(make_config(tmp_path), default_controls()) as gateway:
        await gateway.list_tools()
        body = text_of(await gateway.call_tool("search", {"query": "x"}))
        assert "Do not retry" in body
        assert "Rules:" in body


async def test_every_decision_reaches_the_trace(tmp_path: Path):
    path = tmp_path / "trace.jsonl"
    with TraceWriter(path=path, session="test") as trace:
        async with PolicyGateway(make_config(tmp_path), default_controls(), trace=trace) as gateway:
            await gateway.list_tools()
            await gateway.call_tool("list_documents", {})
            await gateway.call_tool("search", {"query": "x"})

    entries = read_trace(path)
    stages = {e["stage"] for e in entries}
    assert stages == {"discovery", "request", "response"}
    assert any(e["action"] == "block" for e in entries)
    assert all("micros" in e for e in entries)


async def test_trace_records_digests_not_payloads(tmp_path: Path):
    """The trace must not become a second, less protected copy of the data."""
    path = tmp_path / "trace.jsonl"
    with TraceWriter(path=path, session="test") as trace:
        async with PolicyGateway(make_config(tmp_path), default_controls(), trace=trace) as gateway:
            await gateway.list_tools()
            await gateway.call_tool("search", {"query": "x"})

    raw = path.read_text(encoding="utf-8")
    assert "AKIAIOSFODNN7EXAMPLE" not in raw
    assert "Ignore all previous instructions" not in raw
    assert "sha256_16" in raw
