"""Which published attack vectors a gateway at this position can address.

Recall numbers say how well the controls do on attacks they can see. They say nothing
about the attacks they cannot see, and a reader has no way to tell the two apart from a
percentage. This is the other half: the whole published attack surface, with each vector
marked covered, visible but uncovered, or structurally unreachable from here.

The taxonomy is not mine. It is MCPSecBench's (arXiv:2508.13220), 17 attack types across
four surfaces, chosen because it was assembled by people describing the protocol rather
than by me describing my own gateway. Inventing a private taxonomy would let the map be
drawn around whatever happens to be implemented.

Their *data* is not usable here - eleven prompts aimed at a live host, scored by whether
Claude Desktop complied, which is a question about a model rather than about a
protocol-boundary control. Their taxonomy is.

The honest rows are the ones that are not "covered". `OUT_OF_SCOPE` is a claim about where
this gateway sits: it fronts a server and speaks MCP on both sides, so it sees
declarations, arguments and results, and it does not see the user's prompt, the client's
internals, or the transport beneath it. `UNCOVERED` is the roadmap.

    python -m evaluation.coverage      # print the table
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum


class Verdict(StrEnum):
    COVERED = "covered"
    #: The gateway can see it and does nothing about it. This is the roadmap.
    UNCOVERED = "visible, uncovered"
    #: Not reachable from the protocol boundary, whatever controls were added.
    OUT_OF_SCOPE = "out of scope here"


@dataclass(frozen=True, slots=True)
class Vector:
    name: str
    surface: str
    verdict: Verdict
    rationale: str
    controls: tuple[str, ...] = field(default_factory=tuple)


VECTORS: tuple[Vector, ...] = (
    # ---------------------------------------------------------- user interaction
    Vector(
        "Prompt Injection",
        "User Interaction",
        Verdict.OUT_OF_SCOPE,
        "The direct form is a user typing an instruction at the model. That exchange "
        "happens entirely above this gateway, which never sees a prompt - only "
        "declarations, arguments and results. No control placed here could reach it.",
    ),
    Vector(
        'Tool/Service Misuse via "Confused AI"',
        "User Interaction",
        Verdict.COVERED,
        "The model is talked into calling a tool it should not. The gateway does not see "
        "the persuasion, but it does see the call, and deny-by-default plus an approval "
        "gate on irreversible actions is exactly the position from which that is "
        "answerable.",
        ("tool_allowlist", "destructive_action"),
    ),
    Vector(
        "Indirect Prompt Injection",
        "User Interaction",
        Verdict.COVERED,
        "An instruction planted in content a tool returns, which enters context when the "
        "result is read back. This is the case static scanners structurally cannot cover, "
        "because the poisoned result does not exist until the call is made.",
        ("instruction_injection", "budget"),
    ),
    # ---------------------------------------------------------- client / endpoint
    Vector(
        "Schema Inconsistencies",
        "MCP Client/Endpoint",
        Verdict.COVERED,
        "Arguments that do not match the schema the server published, which is decidable "
        "at the request stage against the declaration the server itself gave.",
        ("schema_conformance",),
    ),
    Vector(
        "Slash Command Overlap",
        "MCP Client/Endpoint",
        Verdict.OUT_OF_SCOPE,
        "A host feature: two sources claiming the same slash command in the client's own "
        "command surface. It is resolved before anything reaches MCP, so no traffic "
        "crossing this gateway carries evidence of it.",
    ),
    Vector(
        "Vulnerable Client",
        "MCP Client/Endpoint",
        Verdict.OUT_OF_SCOPE,
        "A flaw in the host application itself. The gateway is downstream of the client "
        "and trusts it by construction; a compromised client can simply not use the "
        "gateway.",
    ),
    # ---------------------------------------------------------- transport
    Vector(
        "MCP Rebinding",
        "MCP Transport",
        Verdict.OUT_OF_SCOPE,
        "DNS rebinding against a locally bound server. It is won or lost in name "
        "resolution and network policy, below the protocol this gateway speaks, and "
        "egress_control reasons about named hosts rather than about what a name resolves "
        "to at connect time.",
    ),
    Vector(
        "Man-in-the-Middle",
        "MCP Transport",
        Verdict.OUT_OF_SCOPE,
        "An attacker on the channel between client and server. That is a transport "
        "security property, answered by TLS and certificate validation, not by a policy "
        "decision about a well-formed message.",
    ),
    # ---------------------------------------------------------- server
    Vector(
        "Tool Poisoning Attack",
        "MCP Server",
        Verdict.COVERED,
        "Instructions planted in the metadata a server presents at registration. This is "
        "the vector measured against MCPTox in section 8, and the one the external "
        "recall number is about.",
        ("instruction_injection",),
    ),
    Vector(
        "Tool Shadowing Attack",
        "MCP Server",
        Verdict.COVERED,
        "A server claiming a tool name another server already owns, which is decidable at "
        "discovery by tracking which server claimed what first.",
        ("tool_shadowing",),
    ),
    Vector(
        "Data Exfiltration",
        "MCP Server",
        Verdict.COVERED,
        "Credentials or content leaving through a tool call or a returned result. Visible "
        "in both directions at this position, which is the argument for being here rather "
        "than scanning declarations only.",
        ("secret_disclosure", "egress_control"),
    ),
    Vector(
        "Package Name Squatting (tool name)",
        "MCP Server",
        Verdict.COVERED,
        "A tool named to be mistaken for a legitimate one. The same name-collision "
        "machinery that answers shadowing answers this, with deny-by-default meaning an "
        "unrecognised name is refused rather than guessed at.",
        ("tool_shadowing", "tool_allowlist"),
    ),
    Vector(
        "Sandbox Escape",
        "MCP Server",
        Verdict.COVERED,
        "A path argument resolving outside the root a filesystem tool is confined to, "
        "which is fully decidable: a path either normalises inside the root or it does "
        "not.",
        ("path_sandbox",),
    ),
    Vector(
        "Package Name Squatting (server name)",
        "MCP Server",
        Verdict.UNCOVERED,
        "The server name is visible on every declaration, so this is reachable, but "
        "nothing here compares a server's claimed identity against anything. Detecting it "
        "needs a notion of which servers are expected, which the gateway does not hold.",
    ),
    Vector(
        "Configuration Drift",
        "MCP Server",
        Verdict.UNCOVERED,
        "A server's declarations changing from what was reviewed. Every declaration "
        "crosses this gateway, so the evidence is here, but nothing is retained between "
        "sessions to compare against. This needs state the gateway deliberately does not "
        "yet keep.",
    ),
    Vector(
        "Rug Pull Attack",
        "MCP Server",
        Verdict.UNCOVERED,
        "A server that behaves until it is trusted, then changes its tool definition. The "
        "same missing capability as configuration drift and the sharper case for it: "
        "every control here judges one event in isolation, so a definition that was benign "
        "on Monday and hostile on Friday is two independent passes, not a change.",
    ),
    Vector(
        "Vulnerable Server",
        "MCP Server",
        Verdict.OUT_OF_SCOPE,
        "A downstream server carrying its own flaw, such as a CVE in its implementation. "
        "The gateway constrains what reaches that server and what comes back, which "
        "narrows exploitation, but it is not a vulnerability scanner and cannot assess "
        "code it never sees.",
    ),
)


def surfaces() -> dict[str, int]:
    """How many vectors sit on each surface, in the paper's order."""
    counts = Counter(v.surface for v in VECTORS)
    return {
        surface: counts[surface]
        for surface in ("User Interaction", "MCP Client/Endpoint", "MCP Transport", "MCP Server")
    }


def tally() -> dict[Verdict, int]:
    counts = Counter(v.verdict for v in VECTORS)
    return {verdict: counts[verdict] for verdict in Verdict}


def table() -> str:
    """The map, as the markdown table the docs carry."""
    lines = ["| Surface | Vector | | Controls |", "|---|---|---|---|"]
    mark = {
        Verdict.COVERED: "covered",
        Verdict.UNCOVERED: "**visible, uncovered**",
        Verdict.OUT_OF_SCOPE: "out of scope here",
    }
    for vector in VECTORS:
        controls = ", ".join(f"`{c}`" for c in vector.controls) or "-"
        lines.append(f"| {vector.surface} | {vector.name} | {mark[vector.verdict]} | {controls} |")
    return "\n".join(lines)


def main() -> None:
    counts = tally()
    print("MCPSecBench taxonomy (arXiv:2508.13220), 17 vectors over four surfaces")
    print()
    for surface, n in surfaces().items():
        print(f"  {surface:<22} {n}")
    print()
    for verdict, n in counts.items():
        print(f"  {verdict.value:<20} {n}")
    print()
    print(table())
    print()
    print("The uncovered rows are the roadmap. Package name squatting by server name,")
    print("configuration drift and rug pull are one missing capability between them:")
    print("nothing here remembers what a server declared last time.")


if __name__ == "__main__":
    main()
