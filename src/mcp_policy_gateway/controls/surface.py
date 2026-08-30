"""Which tools may be called at all, and whether a server is claiming someone else's.

Three controls that share a concern: the *surface* a server is allowed to present.

`ToolAllowlist` is the least clever control here and probably the most valuable. Most of
what an agent should never do, it should never do because the tool was not on the list,
not because a scanner recognised a payload. The default is deny: an empty allowlist
permits nothing. That is deliberate, and a permissive default is the usual way this
control gets quietly turned into decoration.

`ToolShadowing` catches a second server declaring a name an earlier one already owns.
The attack is that a benign-looking server registers `read_file` after the real
filesystem server did, and the client picks the wrong one. It is a fact-based check, so
it either fires or it does not.

`DestructiveAction` does not block. Some calls should happen, just not silently, and a
gateway that can only allow or deny pushes operators into allowing too much. Holding for
a human is the third answer.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..types import Action, Finding, Severity, Stage
from .base import Context, Event


class ToolAllowlist:
    """Denies any tool the operator has not explicitly permitted."""

    name = "tool_allowlist"
    stages = frozenset({Stage.REQUEST})

    def inspect(self, event: Event, context: Context) -> Iterable[Finding]:
        call = event.call
        if call is None:
            return
        if call.tool not in context.allowed_tools:
            yield Finding(
                control=self.name,
                rule="not_allowlisted",
                action=Action.BLOCK,
                severity=Severity.HIGH,
                detail=(
                    f"Tool {call.tool!r} is not in the allowlist "
                    f"({len(context.allowed_tools)} permitted)."
                ),
            )


class ToolShadowing:
    """Flags a server declaring a tool name another server already claimed."""

    name = "tool_shadowing"
    stages = frozenset({Stage.DISCOVERY})

    def inspect(self, event: Event, context: Context) -> Iterable[Finding]:
        declaration = event.declaration
        if declaration is None:
            return
        owner = context.claimed_tools.get(declaration.name)
        if owner is not None and owner != declaration.server:
            yield Finding(
                control=self.name,
                rule="name_already_claimed",
                action=Action.BLOCK,
                severity=Severity.HIGH,
                detail=(
                    f"Server {declaration.server!r} declares {declaration.name!r}, "
                    f"already provided by {owner!r}."
                ),
            )
        else:
            context.claimed_tools.setdefault(declaration.name, declaration.server)


class DestructiveAction:
    """Holds irreversible calls for a human instead of blocking them outright."""

    name = "destructive_action"
    stages = frozenset({Stage.REQUEST})

    def inspect(self, event: Event, context: Context) -> Iterable[Finding]:
        call = event.call
        if call is None or call.tool not in context.destructive_tools:
            return
        if context.approved:
            return
        yield Finding(
            control=self.name,
            rule="approval_required",
            action=Action.REQUIRE_APPROVAL,
            severity=Severity.MEDIUM,
            detail=(
                f"Tool {call.tool!r} has effects that cannot be undone and no approval "
                "was recorded for this call."
            ),
        )
