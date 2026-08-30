"""The gateway itself: an MCP server that fronts another MCP server.

A client connects to this process instead of to the real server. It sees the same tools,
minus any the policy refused to present, and its calls are inspected before being
forwarded and again on the way back. To the client it is an ordinary MCP server; to the
downstream server it is an ordinary MCP client. That shape is the whole point - it means
the enforcement point sits at the protocol boundary and needs no cooperation from either
side, so it works with a server whose source you do not have.

Three places the policy runs, matching the three stages:

  discovery   when the downstream tool list is relayed. A poisoned description is
              dropped or stripped here, before the client ever concatenates it into a
              prompt. This is the only stage where refusing is free - the tool simply
              does not appear.
  request     before forwarding. A refusal here means the downstream server never sees
              the call, which matters when the call itself is the damage.
  response    before the result is handed back. This is the stage a scanner cannot
              occupy, because the content did not exist until now.

The transport is stdio, which is what MCP clients use for local servers, and the
downstream server is launched as a subprocess. Everything is `anyio`-based because the
SDK is; there is no separate event loop here.

Failure policy is fail-closed. If the downstream server dies, or a control raises, the
call is refused rather than passed through. A security control that fails open under load
is not a control.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client

from .controls.base import Context, Control, Event
from .engine import PolicyEngine
from .trace import TraceWriter
from .types import Action, Stage, ToolCall, ToolDeclaration, ToolResult


def _text_of(result: types.CallToolResult) -> str:
    parts: list[str] = []
    for block in result.content or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
    return "\n".join(parts)


def _refusal(reason: str, rules: Sequence[str]) -> types.CallToolResult:
    """What the client gets when the policy refuses.

    Deliberately explicit. A silent failure teaches a model to retry, and a model that
    retries a blocked call burns budget discovering a rule nobody told it about. Naming
    the rules lets it stop, and lets a person reading the transcript see why.
    """
    detail = ", ".join(rules) if rules else "policy"
    return types.CallToolResult(
        content=[
            types.TextContent(
                type="text",
                text=(
                    f"Refused by mcp-policy-gateway: {reason}\n"
                    f"Rules: {detail}\n"
                    "This call was not forwarded. Do not retry it unchanged."
                ),
            )
        ],
        is_error=True,
    )


@dataclass(slots=True)
class GatewayConfig:
    """How to reach the downstream server and what the policy is allowed to permit."""

    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None
    server_name: str = "downstream"
    context: Context = field(default_factory=Context)
    #: Present a tool the policy would refuse at discovery, or hide it entirely.
    hide_refused_tools: bool = True


class PolicyGateway:
    """Wraps one downstream MCP server behind a policy engine."""

    def __init__(
        self,
        config: GatewayConfig,
        controls: Sequence[Control],
        trace: TraceWriter | None = None,
    ) -> None:
        self.config = config
        self.engine = PolicyEngine(controls=list(controls))
        self.trace = trace
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None
        #: Declarations the policy allowed, by tool name.
        self.permitted: dict[str, ToolDeclaration] = {}
        #: Tools refused at discovery, and the rules that refused them.
        #:
        #: Hiding a tool from the listing is not the same as making it uncallable. A
        #: client that has the name from an earlier session, or that guesses it, can
        #: still ask for it - and the request-stage controls have no idea the
        #: declaration was rejected, because they only see the call. Without this the
        #: demo happily ran a tool it had just withheld, which is the kind of gap that
        #: makes a boundary decorative.
        self.withheld: dict[str, list[str]] = {}

    # ---------------------------------------------------------------- lifecycle
    async def __aenter__(self) -> PolicyGateway:
        self._stack = AsyncExitStack()
        params = StdioServerParameters(
            command=self.config.command, args=self.config.args, env=self.config.env
        )
        read, write = await self._stack.enter_async_context(stdio_client(params))
        self._session = await self._stack.enter_async_context(ClientSession(read, write))
        await self._session.initialize()
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._stack is not None:
            await self._stack.aclose()
        self._stack = None
        self._session = None

    @property
    def session(self) -> ClientSession:
        if self._session is None:
            raise RuntimeError("gateway is not connected; use it as an async context manager")
        return self._session

    # ---------------------------------------------------------------- discovery
    async def list_tools(self) -> list[types.Tool]:
        """Relay the downstream tool list, minus anything the policy refuses."""
        listing = await self.session.list_tools()
        allowed: list[types.Tool] = []

        for tool in listing.tools:
            declaration = ToolDeclaration(
                server=self.config.server_name,
                name=tool.name,
                description=tool.description or "",
                input_schema=tool.input_schema or {},
            )
            started = time.perf_counter()
            decision = self.engine.evaluate(
                Event(stage=Stage.DISCOVERY, declaration=declaration), self.config.context
            )
            micros = (time.perf_counter() - started) * 1e6
            if self.trace is not None:
                self.trace.record(
                    stage=Stage.DISCOVERY, decision=decision, tool=tool.name, micros=micros
                )

            if decision.action is Action.BLOCK:
                self.withheld[tool.name] = decision.rules
                if self.config.hide_refused_tools:
                    continue
                # Presented but neutered: the name survives so a client that hard-codes
                # it gets a clear refusal instead of a confusing absence.
                tool = tool.model_copy(
                    update={"description": f"[withheld by policy: {', '.join(decision.rules)}]"}
                )
            elif decision.action is Action.SANITISE and decision.sanitised_text is not None:
                tool = tool.model_copy(update={"description": decision.sanitised_text})

            self.permitted[tool.name] = declaration
            allowed.append(tool)

        # Schema-aware controls only work if they have seen the schemas.
        for control in self.engine.controls:
            learn = getattr(control, "learn", None)
            if callable(learn):
                for tool in allowed:
                    learn(tool.name, tool.input_schema or {})

        return allowed

    # ------------------------------------------------------------------- calls
    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> types.CallToolResult:
        """Inspect, forward, inspect again."""
        call = ToolCall(server=self.config.server_name, tool=name, arguments=dict(arguments or {}))

        # A tool refused at discovery stays refused, whether or not it was listed. The
        # declaration was rejected; the request-stage controls cannot know that, because
        # they only ever see the call.
        if name in self.withheld:
            return _refusal(
                "this tool was withheld when the server declared it", self.withheld[name]
            )

        started = time.perf_counter()
        request_decision = self.engine.evaluate(
            Event(stage=Stage.REQUEST, call=call), self.config.context
        )
        micros = (time.perf_counter() - started) * 1e6
        if self.trace is not None:
            self.trace.record(
                stage=Stage.REQUEST, decision=request_decision, call=call, micros=micros
            )

        if request_decision.action is Action.BLOCK:
            return _refusal("the request violates policy", request_decision.rules)
        if request_decision.action is Action.REQUIRE_APPROVAL:
            return _refusal(
                "this action needs human approval and none was recorded", request_decision.rules
            )

        try:
            downstream = await self.session.call_tool(name, arguments or {})
        except Exception as error:  # fail closed
            failure = ToolResult(text=str(error), is_error=True)
            decision = self.engine.evaluate(
                Event(stage=Stage.RESPONSE, result=failure, origin=call), self.config.context
            )
            if self.trace is not None:
                self.trace.record(
                    stage=Stage.RESPONSE, decision=decision, call=call, result=failure
                )
            return _refusal(f"the downstream server failed: {type(error).__name__}", [])

        result = ToolResult(text=_text_of(downstream), is_error=bool(downstream.is_error))
        started = time.perf_counter()
        response_decision = self.engine.evaluate(
            Event(stage=Stage.RESPONSE, result=result, origin=call), self.config.context
        )
        micros = (time.perf_counter() - started) * 1e6
        if self.trace is not None:
            self.trace.record(
                stage=Stage.RESPONSE,
                decision=response_decision,
                call=call,
                result=result,
                micros=micros,
            )

        if response_decision.action is Action.BLOCK:
            return _refusal("the tool result violates policy", response_decision.rules)
        if response_decision.action is Action.SANITISE and response_decision.sanitised_text:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=response_decision.sanitised_text)],
                is_error=downstream.is_error,
            )
        return downstream
