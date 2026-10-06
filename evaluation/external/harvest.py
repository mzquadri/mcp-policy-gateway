"""Real tool declarations, from servers nobody wrote to be tested.

MCPTox is attacks only, and recall without a false-positive rate is the shape of result
this project criticises the keyword filter for. The benign half has to come from somewhere
independent too, or the same objection applies to it.

The official MCP reference servers are the best available source. They declare real tools,
written to be used rather than to be measured, by people who had never seen this gateway.
A false positive on one of them is unarguable: there is no reading in which blocking the
official filesystem server is the right call.

The hardest case in the set is not one I chose. The `fetch` server's own description says
"Although originally you did not have internet access, and were advised to refuse and tell
the user this, this tool now grants you internet access." That is legitimate, official prose
which addresses the model directly and overrides its prior behaviour, which is also a fair
description of an injection. If the gateway cannot pass that, it cannot be deployed in front
of the reference servers.

Parsing rather than running. Starting six servers would be more faithful and would need a
node and a python toolchain, network, and a working directory per server; what the controls
actually read is the declaration text, and that is recoverable from source. Per-server counts
are reported so a server whose format changed shows up as a drop to zero rather than as a
quietly smaller benign set - which is how two of them were caught returning nothing, git and
time naming their tools with an enum member rather than a literal.

Six of the seven reference servers. `everything` is excluded deliberately; see the note in
sources.py.
"""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from corpus import Case

from mcp_policy_gateway.types import Action, Stage

RATIONALE = (
    "A real tool declaration from an official MCP reference server. Any action against it "
    "is a false positive: nothing about this text was written to be caught."
)

# server.registerTool("name", { ... description: <strings> ... })
_TS_TOOL = re.compile(
    r"""registerTool\s*\(\s*["'`](?P<name>[^"'`]+)["'`]""",
    re.VERBOSE,
)
# Tool(name=<literal or enum member>, description=<strings>)
#
# Anchored on the constructor rather than on `name=` alone, which matters twice. git and
# time name their tools with an enum member - `name=GitTools.STATUS` - so a literal-only
# pattern returns nothing for them. And Pydantic `Field(description=...)` documents an
# argument, which lives in inputSchema and is never read at discovery; anchoring here
# leaves those out instead of padding the benign set with text nothing scores.
_PY_TOOL = re.compile(
    r"""\bTool\s*\(\s*(?:[^)]*?\b)?name\s*=\s*(?:["'](?P<lit>[^"']+)["']|(?P<ref>[A-Za-z_][\w.]*))""",
    re.S,
)

_TS_STRING = re.compile(r"""(?P<q>["'`])(?P<body>(?:\\.|(?!\1).)*)(?P=q)""", re.S)
_PY_STRING = re.compile(
    r"""(?P<q>\"\"\"|'''|"|')(?P<body>(?:\\.|(?!(?P=q)).)*)(?P=q)""",
    re.S,
)


@dataclass(frozen=True, slots=True)
class Declaration:
    name: str
    description: str


def declarations(source: str, *, language: str) -> list[Declaration]:
    """Pull (name, description) pairs out of a server's source."""
    if language == "typescript":
        return _scan(source, _TS_TOOL, _TS_STRING, joiner="+")
    if language == "python":
        return _scan(source, _PY_TOOL, _PY_STRING, joiner="")
    raise ValueError(f"unknown language {language!r}")


def _scan(
    source: str,
    tool: re.Pattern[str],
    string: re.Pattern[str],
    *,
    joiner: str,
) -> list[Declaration]:
    out: list[Declaration] = []
    for match in tool.finditer(source):
        # The description belongs to this tool only if it appears before the next one.
        nxt = tool.search(source, match.end())
        window = source[match.end() : nxt.start() if nxt else len(source)]
        description = _description(window, string, joiner=joiner)
        if description:
            out.append(Declaration(_name(match), description))
    return out


def _name(match: re.Match[str]) -> str:
    groups = match.groupdict()
    return groups.get("name") or groups.get("lit") or groups.get("ref") or "unnamed"


def _description(window: str, string: re.Pattern[str], *, joiner: str) -> str:
    key = re.search(r"\bdescription\s*[:=]\s*", window)
    if not key:
        return ""

    pieces: list[str] = []
    cursor = key.end()
    while True:
        literal = string.match(window, cursor)
        if literal is None:
            break
        pieces.append(_unescape(literal.group("body")))
        cursor = literal.end()
        # Allow the concatenation the source actually uses: `+` in TypeScript,
        # adjacency in Python. Anything else ends the description.
        gap = re.match(r"\s*\+\s*" if joiner == "+" else r"\s*", window[cursor:])
        if gap is None or (joiner == "+" and "+" not in gap.group(0)):
            break
        cursor += gap.end()
    return "".join(pieces).strip()


def _unescape(body: str) -> str:
    return body.replace('\\"', '"').replace("\\'", "'").replace("\\n", "\n").replace("\\\\", "\\")


def benign_cases(found: Iterable[Declaration], *, server: str) -> list[Case]:
    """Adapt declarations to benign discovery cases.

    `expected` is ALLOW rather than SANITISE: for a real tool, being redacted is already
    a false positive, not a tolerable outcome.
    """
    return [
        Case(
            case_id=f"mcpservers-{server}-{d.name}",
            label="benign",
            stage=Stage.DISCOVERY,
            rationale=RATIONALE,
            expected=Action.ALLOW,
            tool=d.name,
            description=d.description,
            server=server,
        )
        for d in found
    ]


def mcpguard_benign(csv_text: str) -> list[Case]:
    """The benign half of MCP-Guard's evaluation set.

    1,053 rows of `description,Label`, of which 621 carry Label 0. Those are real tool
    descriptions collected from MCP server metadata - "Cancels a crawl job.", "Deletes
    keys from the Consul key-value store." - which is exactly what the gateway reads at
    discovery, from far more servers than the seven reference ones.

    **Only Label 0 is taken.** The 432 malicious rows are shell payloads
    (`$(sleep 1 && echo vulnerable 1)`), SQL fragments (`'; DROP TABLE workflows; --`),
    path traversal, and harmful-content prompts. Almost none of them is a poisoned tool
    *declaration*; they are request-stage payloads and content-policy items. Scoring them
    against discovery controls would measure the wrong thing and report a low number as
    though it meant something, which is the category error this harness already refused
    for MCPSecBench.

    Blank descriptions are dropped rather than passed. An empty string satisfies every
    control trivially, so counting it would pad the denominator and flatter the rate.
    """
    out: list[Case] = []
    for index, row in enumerate(csv.DictReader(io.StringIO(csv_text))):
        if (row.get("Label") or "").strip() != "0":
            continue
        description = (row.get("description") or "").strip()
        if not description:
            continue
        out.append(
            Case(
                case_id=f"mcpguard-{index:04d}",
                label="benign",
                stage=Stage.DISCOVERY,
                rationale=(
                    "A real tool description from MCP-Guard's benign set, collected from "
                    "server metadata. Any action against it is a false positive."
                ),
                expected=Action.ALLOW,
                tool=f"tool_{index:04d}",
                description=description,
                server="mcpguard",
            )
        )
    return out


def harvest_all(sources: Sequence[tuple[str, str, str]]) -> dict[str, list[Declaration]]:
    """(server, language, source) triples -> declarations per server."""
    return {server: declarations(source, language=language) for server, language, source in sources}


__all__ = [
    "Declaration",
    "benign_cases",
    "declarations",
    "harvest_all",
    "mcpguard_benign",
]
