"""What is scored, where it came from, and on whose terms.

Each entry pins a single file to a single commit and a single digest. Pins are changed
deliberately and the change is recorded in the write-up, never adjusted to make a run pass.

On licensing. MCPTox publishes no LICENSE, so default copyright applies: the work may be
read and cited, and is not redistributed here. Nothing in this repository contains their
payloads, and `.cache/` is gitignored. A reader reproduces a run by fetching from their
repository, which is where the citation points.
"""

from __future__ import annotations

from .fetch import Source

#: MCPTox, AAAI 2026. Poisoned tool descriptions harvested from real MCP servers.
#:
#: The paper reports 1,348 malicious cases; this file holds 485 tool records across 45
#: servers, and 485 is what gets scored. The discrepancy is not explained in their
#: repository, so the write-up states what was actually read rather than what the paper
#: counts.
MCPTOX = Source(
    name="mcptox-pure-tool",
    ref="f85189f9ad12504c197c7f920ab818a40657b1fa",
    url=(
        "https://raw.githubusercontent.com/zhiqiangwang4/MCPTox-Benchmark/"
        "f85189f9ad12504c197c7f920ab818a40657b1fa/pure_tool.json"
    ),
    sha256="54b1eb0e9d7b2f18465266aa9d9dfda828cd558b1269b74731ec2c5d8579e617",
    citation=(
        "Wang et al., MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP "
        "Servers. Proceedings of the AAAI Conference on Artificial Intelligence, 2026. "
        "https://github.com/zhiqiangwang4/MCPTox-Benchmark"
    ),
    licence=(
        "No LICENSE published in the source repository; default copyright applies. "
        "Fetched at evaluation time, cited, and not redistributed."
    ),
)

#: The official MCP reference servers, for the benign half.
#:
#: Apache-2.0 for new contributions, MIT for those not yet relicensed, per their LICENSE.
#: Both permit reuse, but the same no-vendoring rule applies anyway: pinned and fetched,
#: never copied in. That keeps one rule for every external source rather than one rule per
#: licence, and keeps the mixed-licence question out of this repository entirely.
_SERVERS_REF = "5abed86c5317b833dd59907492d56c65981642aa"
_SERVERS_CITATION = (
    "Official Model Context Protocol reference servers, "
    "https://github.com/modelcontextprotocol/servers"
)
_SERVERS_LICENCE = "Apache-2.0 and MIT (mixed, per their LICENSE). Fetched, not vendored."


def _server(name: str, path: str, sha256: str) -> Source:
    return Source(
        name=f"mcpservers-{name}",
        ref=_SERVERS_REF,
        url=f"https://raw.githubusercontent.com/modelcontextprotocol/servers/{_SERVERS_REF}/{path}",
        sha256=sha256,
        citation=_SERVERS_CITATION,
        licence=_SERVERS_LICENCE,
    )


#: (server, language, Source). Languages differ because the servers do.
REFERENCE_SERVERS: tuple[tuple[str, str, Source], ...] = (
    (
        "filesystem",
        "typescript",
        _server(
            "filesystem",
            "src/filesystem/index.ts",
            "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
        ),
    ),
    (
        "memory",
        "typescript",
        _server(
            "memory",
            "src/memory/index.ts",
            "fa1d38913ecdfca22231dbcf3b047548417f2ca862ef42de69394883223c32b6",
        ),
    ),
    (
        "sequentialthinking",
        "typescript",
        _server(
            "sequentialthinking",
            "src/sequentialthinking/index.ts",
            "fab7b6e9817d67fe83fdc4f4b1d18bb3a2c034cbd8066b0ec84d85679d13c22c",
        ),
    ),
    # `everything` is deliberately absent. Its index.ts is a transport launcher and its
    # tools live one per file under src/everything/tools/, so including it means either
    # fifteen more pins or an arbitrary subset, and an arbitrary subset is the selection
    # bias this whole exercise exists to avoid. It is also a protocol demonstration
    # server - elicitation triggers, sampling requests - rather than tools anyone
    # deploys, so it is the least representative of the seven. Six servers, 39 real
    # declarations, and the omission stated rather than reported as a zero.
    (
        "fetch",
        "python",
        _server(
            "fetch",
            "src/fetch/src/mcp_server_fetch/server.py",
            "f66dc973126c9251934fdb5355fa960529546660cad74147a6b31f725a79b358",
        ),
    ),
    (
        "git",
        "python",
        _server(
            "git",
            "src/git/src/mcp_server_git/server.py",
            "027d1158d3df34a3acf4249dcaabe0687c4bfa4aaf36fb29196ddb2481e44394",
        ),
    ),
    (
        "time",
        "python",
        _server(
            "time",
            "src/time/src/mcp_server_time/server.py",
            "629500285347db06939c59f4cfd9004cc86ebb1adb68442cfc1678c2e54f6292",
        ),
    ),
)

ALL: tuple[Source, ...] = (MCPTOX, *(source for _, _, source in REFERENCE_SERVERS))

__all__ = ["ALL", "MCPTOX", "REFERENCE_SERVERS"]
