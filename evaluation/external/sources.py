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

ALL: tuple[Source, ...] = (MCPTOX,)

__all__ = ["ALL", "MCPTOX"]
