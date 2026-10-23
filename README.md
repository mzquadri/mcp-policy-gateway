<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/header-dark.png">
  <img alt="A gateway that refuses, nine controls at the three points where an MCP tool call is untrusted, with a bar chart showing the policy gateway catching 96.2% of attacks against a keyword filter's 38.5%" src="docs/assets/header-light.png">
</picture>

# mcp-policy-gateway

An MCP server that sits in front of another MCP server and decides, call by call, what is
allowed through. It is for anyone running Model Context Protocol tools against servers they
do not control, where a poisoned tool description or a poisoned search result reaches the
model's context before anybody reviews it. It ships with a deterministic benchmark, so the
question "which control actually stops which attack" has an answer you can re-run.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/architecture-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/architecture.svg">
  <img src="docs/architecture.svg" alt="Architecture: MCP client to policy gateway to downstream server, with a JSONL trace">
</picture>

## The result

47 cases: 26 attacks and 21 benign near-misses. No model calls, no network.
`python evaluation/benchmark.py` reproduces every rate below exactly on any machine.

| Configuration | Attacks caught | Benign refused | Benign untouched | Median decision |
|---|---|---|---|---|
| **baseline** (no gateway) | 0.0% | 0.0% | 100.0% | 1 µs |
| **keyword filter** | 38.5% | 33.3% | 66.7% | 5 µs |
| **gateway** | **96.2%** | **9.5%** | 76.2% | 191 µs |

The decision-time column is the exception to "reproduces exactly": it is a property of the
machine it ran on, not of the system. Read only its order of magnitude. Across eight runs
on one machine the gateway's median ranged from **191 µs to 710 µs**, the high end while
that machine was busy with unrelated work. The four rate columns did not move at all
across those runs, to the digit.

The keyword filter is in there because it is the real alternative. "We added a filter" is
what actually happens when a team decides to do something about prompt injection, and
comparing only against *nothing* would flatter the result. It catches a third of the
attacks and refuses one in three legitimate calls, which is the profile of a control that
gets switched off in week two.

Scored separately against three external corpora nobody here wrote, details in
[Scored against a corpus I did not write](#scored-against-a-corpus-i-did-not-write).

## Run it

Python 3.11 or newer. `pyproject.toml` sets `requires-python = ">=3.11"`, and CI runs the
whole thing on 3.11, 3.12 and 3.13.

```bash
python -m venv .venv && . .venv/Scripts/activate     # or bin/activate
pip install -e ".[dev]"

python -m mcp_policy_gateway.cli demo                # real MCP process, real stdio
python evaluation/benchmark.py                       # the table above
pytest                                               # the test suite
```

`make check` runs what CI runs: ruff, mypy, pytest and the benchmark. Everything above is
offline.

`demo` launches a deliberately hostile MCP server from `examples/`, drives it through the
gateway and prints every decision. It needs no API key, no network and no configuration.
That is the point: an evaluation that needs a key is an evaluation nobody re-runs.

To put the gateway in front of a server you already use:

```bash
python -m mcp_policy_gateway.cli proxy \
  npx -y @modelcontextprotocol/server-filesystem /srv/docs \
  --sandbox /srv/docs \
  --allow read_file --allow list_directory \
  --destructive write_file \
  --allow-host docs.internal.example.com
```

---

## The problem

An MCP client hands a model a set of tools, calls them on the model's behalf, and feeds
the results back into context. Three things in that loop are untrusted, and they are
untrusted at different times:

1. **Tool declarations.** A server describes its own tools. A description is prose that
   most clients concatenate into a prompt, so a server can put instructions there.
2. **Call arguments.** Built by a model from a schema, then sent to a server that may or
   may not validate them.
3. **Tool results.** Whatever comes back is read into context. It is a document, a search
   result, a database row. It is content the server did not write and cannot vouch for.

The security tooling that exists for MCP today is mostly **static scanners**: point them
at a server, they read the declarations and report suspicious ones. That is worth doing
and it covers exactly one of the three. It cannot cover the third at all, because a
poisoned search result does not exist until someone runs the search.

This project puts the enforcement point at the protocol boundary instead, where all three
are visible, and then measures how much that is worth.

## What it is

An MCP server that fronts another MCP server. Your client connects to the gateway; the
gateway connects to the real server. Both sides speak ordinary MCP, so it works with a
server whose source you do not have.

```mermaid
flowchart LR
    C["MCP client<br/>host and model"]
    S["downstream MCP server<br/>source you do not control"]

    subgraph GW["mcp-policy-gateway"]
        direction TB
        D["<b>discovery</b><br/>what the server says its tools are"]
        RQ["<b>request</b><br/>what the model is about to call"]
        RS["<b>response</b><br/>what came back"]
    end

    C -- "list tools" --> D
    D -- "declarations, some withheld" --> C
    C -- "call tool" --> RQ
    RQ -- "allowed call" --> S
    S -- "result" --> RS
    RS -- "result, allowed or redacted" --> C

    D --> T["JSONL trace<br/>digests, not payloads"]
    RQ --> T
    RS --> T

    linkStyle 0,2,3 stroke:#2563EB
    linkStyle 1,4,5 stroke:#059669
    linkStyle 6,7,8 stroke:#9CA3AF,stroke-dasharray: 4 3
```

Each stage is a different problem. Discovery is prose the server wrote about itself.
Request is a call the model built. Response is content the server fetched and cannot
vouch for. A scanner that reads declarations covers the first and structurally cannot
reach the third, because a poisoned search result does not exist until the search runs.

Nine controls run at those three stages:

| Control | Stage | What it decides |
|---|---|---|
| `tool_allowlist` | request | Whether this tool may be called at all. Deny by default. |
| `tool_shadowing` | discovery | Whether a server is claiming a name another already owns. |
| `destructive_action` | request | Whether an irreversible call has a recorded approval. |
| `schema_conformance` | request | Whether arguments match the schema the server published. |
| `path_sandbox` | request | Whether a path argument resolves inside the sandbox root. |
| `budget` | request, response | Call counts, output bytes, and a per-tool circuit breaker. |
| `secret_disclosure` | request, response | Whether a credential is passing in either direction. |
| `egress_control` | request, response | Whether a named host is on the egress allowlist. |
| `instruction_injection` | discovery, response | Whether text contains instructions aimed at the model. |

A control never decides on its own. It reports findings; the engine combines them, and
the strongest action wins: allow, sanitise, hold for approval, or block.

```mermaid
flowchart LR
    EV["one event<br/>a declaration, a call<br/>or a result"] --> RUN

    subgraph RUN["every control for that stage runs"]
        direction TB
        K1["control"]
        K2["control"]
        K3["control"]
    end

    RUN --> FI["findings<br/>each with a severity<br/>and a proposed action"]
    FI --> ENG{"engine takes the<br/><b>strongest</b> action"}

    ENG --> A["<b>allow</b><br/>pass it through"]
    ENG --> SA["<b>sanitise</b><br/>redact the span,<br/>keep the rest"]
    ENG --> AP["<b>require_approval</b><br/>hold for a human"]
    ENG --> BL["<b>block</b><br/>refuse, and say which rule"]

    linkStyle 3 stroke:#059669
    linkStyle 4 stroke:#D97706
    linkStyle 5 stroke:#D97706
    linkStyle 6 stroke:#2563EB
```

Controls keep running after one of them has already decided to block. That costs a little
time and buys the per-control table further down: if the engine stopped at the first
block, each control's count would depend on the order they happen to run in, and the
table would measure the ordering rather than the control.

## Reading the result

![What each option costs](docs/figures/01_tradeoff.png)

### How much of that gap the corpus can support

Every rate above is a count over 26 attacks or 21 benign cases. At those sizes a
percentage to one decimal place reads as more precise than it is, so the benchmark also
prints a 95% Wilson interval for each. Wilson rather than the usual normal approximation,
which at 25 of 26 puts the upper bound past 1 and at 0 of 21 claims no uncertainty at all.

| Configuration | Attacks caught | Benign refused |
|---|---|---|
| **baseline** (no gateway) | 0.0% [0.0%, 12.9%] | 0.0% [0.0%, 15.5%] |
| **keyword filter** | 38.5% [22.4%, 57.5%] | 33.3% [17.2%, 54.6%] |
| **gateway** | 96.2% [81.1%, 99.3%] | 9.5% [2.7%, 28.9%] |

The two columns say different things and should be read differently.

**On recall the gap is real.** The gateway's [81.1%, 99.3%] does not come near the keyword
filter's [22.4%, 57.5%]. Twenty-six cases are few, but not so few that this separation
could be luck.

**On false refusals it is not established.** [2.7%, 28.9%] against [17.2%, 54.6%] overlap
across most of their width. The gateway refused two legitimate calls where the filter
refused seven, and on 21 cases that is the direction the evidence points rather than a
finding to quote. Claiming otherwise would be the error this project exists to avoid.

The intervals cover sampling error only: how much these rates would move on another 47
cases written the same way, and nothing about real traffic.

![Coverage by attack class](docs/figures/02_by_attack_class.png)

### Per control, on the same run

| Control | Attacks caught | Benign cases touched |
|---|---|---|
| `instruction_injection` | 16 | 5 |
| `egress_control` | 4 | 0 |
| `path_sandbox` | 4 | 0 |
| `secret_disclosure` | 3 | 0 |
| `schema_conformance` | 2 | 0 |
| `tool_allowlist` | 2 | 0 |
| `tool_shadowing` | 1 | 0 |
| `destructive_action` | 1 | 0 |
| `budget` | 1 | 0 |

![Per control contribution](docs/figures/03_controls.png)

Every benign case that gets touched is touched by the one control that has to make a
judgement call. The eight deterministic controls have no false positives on this corpus,
which is the argument for keeping the judgement in exactly one place.

## Where it fails

Three cases out of 47 are not handled, and all three were written before the controls
were. They stay in the corpus and stay scored, because deleting a case you cannot handle
is how a benchmark stops measuring anything.

`inject-006` used to be a fourth. It was a base64 override instruction with no plaintext
around it, and the stated reason for leaving it was sound: decoding every base64-looking
span before matching would flag legitimate encoded attachments. What closed it was
narrowing the decode rather than accepting the cost. A span is only re-scanned if it
decodes to valid UTF-8 that reads as prose, so an image, an archive, a key and a digest
are all dropped before any rule sees them. Three benign cases were added at the same time
to measure that: an encoded attachment, encoded release notes carrying the override rule's
entire vocabulary without an imperative, and an advisory quoting the payload it warns
about. None of them is a false positive, and the advisory is sanitised rather than
refused. The decode can be turned off, and the benchmark can be run either way.

| Case | What it is | Why it fails |
|---|---|---|
| `secret-004` | A bare 64-hex-character credential | Catching it means flagging every SHA-256 digest in every document. The control keys on prefixes and assignment shape instead. |
| `fp-known-001` | A runbook saying "ignore the previous instructions in section 3" | Genuine operator prose with the exact shape of an attack. There is no signal available that separates them. |
| `fp-known-002` | Onboarding text asking someone to "show your system prompt" | Same problem. Internal documentation discusses prompts now. |

![Where it fails](docs/figures/04_failures.png)

The two false positives are the honest cost of the injection control, and they are the
reason it is the only control allowed to be uncertain. Both survived the decode: they are
plaintext, and nothing about reading one encoding layer deeper helps with a sentence whose
meaning depends on who is being addressed. Full write-up in
[`docs/learning/06_failures.md`](docs/learning/06_failures.md).

## Scored against a corpus I did not write

Everything above is measured on 47 cases I wrote, which is the standard weakness of a
self-built benchmark. So the gateway was also run against [MCPTox](https://github.com/zhiqiangwang4/MCPTox-Benchmark)
(AAAI 2026), 485 poisoned tool declarations harvested from real MCP servers by people who
had never seen this project.

| | caught | 95% Wilson |
|---|---|---|
| my corpus, 26 attacks | 96.2% | [81.1%, 99.3%] |
| MCPTox, 485 declarations, as the gateway stood | **11.3%** | [8.8%, 14.5%] |
| MCPTox, after the changes it prompted | **55.1%** | [50.6%, 59.4%] |

The first number is the useful one. `mandatory_tool_precondition` bounded the gap between
"before" and the obligation at 40 characters, which fits how *I* write a case and not how
anyone else does; 72 of the 103 missed declarations carrying that pair exceeded it. A second
attack class, a declaration claiming priority over the user, then coercing an argument
value, had no rule at all. Neither could have been found on 47 cases of mine.

The internal numbers did not move through either change, including the benign cases that
caused that rule to be narrowed in the first place.

The benign half is external too, because recall without a false-positive rate is the shape
of result this project criticises the keyword filter for. Scored against **660 real tool
declarations**, harvested from the official MCP reference servers and from MCP-Guard's
benign set, the gateway blocks **0** and touches **0**, interval [0.0%, 0.6%].

That includes the `fetch` server's own description, which tells the model it was "advised to
refuse and tell the user this" and that it may now do otherwise. Official prose with the
shape of an injection, and it passes.

A second external source, [MSB](https://github.com/dongsenzhang/MSB) (ICLR 2026), reaches
the stage none of the above does: fifteen attacks arriving inside **tool results**, which is
the case a static scanner structurally cannot cover. The gateway caught **0 of 15**. Three
wrappers failed for three reasons, the first being that `mandatory_tool_precondition` knew
`call`, `invoke`, `execute` and `run` but not **`use`**, the most ordinary word for invoking
a tool. After fixes taken from threat rules ATR-2026-01302 and ATR-2026-01751 it catches
15/15, and MCPTox rose 49.5% to 55.1% at no false-positive cost. That transfer, from a fix
found on one corpus to a corpus by different authors, is the least circular evidence here.

**55.1% should not be read as generalisation.** A large part of the gain is one rule whose
trigger phrase appears in 0% of their first two generators and 35% of the third, one
generator's opening sentence, not a property of tool poisoning. 218 of 485 are still missed
and the three generators disagree at 39.0%, 56.3% and 59.6%. These rates also are not
comparable to the ones in their paper: MCPTox scores whether a *model complies*, this scores
whether a *control fires*.

The changes that produced it came from reading published work rather than inventing rules:
two detection rules transcribed from [MCP-Guard](https://github.com/GenTelLab/MCP-Guard),
the localisation gap closed from threat rule ATR-2026-00148, and `argument_coercion`
rebuilt as weighted scoring against a threshold after MCP-Guard's `shadow_rules.json`,
which alone was worth ten points of recall at no false-positive cost. Both decision
conventions are now reported, following [CASCADE](https://arxiv.org/abs/2604.17125).

### Where the external corpora are pinned

Every external source is one entry in
[`evaluation/external/sources.py`](evaluation/external/sources.py), and each entry pins a
single file to a single commit and a single SHA-256 digest, alongside its citation and its
licence terms. Nothing of theirs is copied into this repository. MCPTox and MCP-Guard publish
no licence, so default copyright applies and the files are fetched at evaluation time into a
gitignored `.cache/`; MSB is MIT and is still fetched rather than vendored, because one rule
for every source is easier to keep than one rule per licence. Pins are changed deliberately
and the change is recorded in the write-up, never adjusted to make a run pass.

`make check` and `make bench` stay offline. Only `bench-external` touches the network, and
only on a cold cache.

```bash
make bench-external     # fetches once, then deterministic
```

Full write-up, including what it does not establish, in
[`docs/learning/08_external_validation.md`](docs/learning/08_external_validation.md).

### What it cannot see

A recall number over a corpus of tool poisoning is silent about the other sixteen things on
the published list. So the nine controls are also mapped against MCPSecBench's taxonomy of
17 attack vectors across four surfaces: **8 covered, 3 visible but uncovered, 6 structurally
out of reach** from a position at the protocol boundary.

The three uncovered ones are a single missing capability. Package name squatting by server
name, configuration drift and rug pull are all visible here, and none is addressed, because
every control is a pure function of one event: *nothing remembers what a server declared
last time*. A definition that was benign on Monday and hostile on Friday is two independent
evaluations, both correct, and the change between them is the attack.

```bash
make coverage-map
```

The map is data in `evaluation/coverage.py`, not prose, and tests hold it to the taxonomy
and to the control set in both directions. Full reasoning per vector in
[`docs/learning/09_coverage.md`](docs/learning/09_coverage.md).

## Upstream foundation

This is an original implementation. It is not a fork and no third-party source is
vendored here.

- **[MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)** (MIT) is a
  dependency. The gateway speaks MCP through it rather than reimplementing the wire
  format. Targets the 2.x API, where `FastMCP` became `MCPServer`.
- **Prior art, read but not used as code:** [OWASP MCP Tool
  Poisoning](https://owasp.org/www-community/attacks/MCP_Tool_Poisoning) for the threat
  vocabulary, and [Snyk `agent-scan`](https://github.com/snyk/agent-scan) (Apache-2.0) as
  the reference example of the static-scanning approach this measures itself against.

Full attribution in [`NOTICE`](NOTICE).

## What is mine

The gateway, all nine controls, the policy engine, the corpus, the benchmark, the trace
format and the CLI. Specifically:

- **Three-stage enforcement.** Splitting discovery, request and response, so response-
  stage attacks are reachable at all.
- **A corpus with ground truth per case.** 26 attacks, 21 benign near-misses. Each case
  states the weakest acceptable response, because "block everything" is wrong for a
  credential inside a legitimate document.
- **Benign near-misses as a first-class half.** The false-positive rate is what decides
  whether a control survives contact with an operator, and it is the number the keyword
  baseline loses on.
- **Context-demotion in the injection control.** Quoted, fenced and reported text demotes
  a finding from block to redact, which is what makes a security advisory readable.
- **Per-control attribution.** Every control runs even after another has blocked, so the
  effectiveness table is not an artefact of ordering.
- **Fail-closed proxying** over real stdio MCP, with a JSONL trace that stores digests
  rather than payloads.

## Figures

Generated from `assets/results.json` and the control registry, so they cannot describe a
system the code does not have:

```bash
python scripts/figures/generate_diagram.py   # docs/architecture.svg
python scripts/figures/generate_figures.py   # docs/figures/*.png
```

`assets/results.json` stamps the commit it was generated from, so staleness is visible
rather than assumed. Regenerate it with `make evidence` after any change that moves a
number. The rate columns in the tables above do not depend on `assets/` either way: they
are pinned by `tests/test_corpus_and_benchmark.py` against a fresh benchmark run.

## Documentation

`docs/learning/` works from the problem up: what MCP is and why its trust boundary is
unusual, the threat model, the architecture, the implementation, how the evaluation is
constructed, where it fails, and what to try next.

## Licence

MIT. See [`LICENSE`](LICENSE).
