# mcp-policy-gateway

Runtime policy enforcement for Model Context Protocol tool calls, and a deterministic
benchmark that measures which controls actually stop which attacks.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/architecture-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/architecture.svg">
  <img src="docs/architecture.svg" alt="Architecture: MCP client to policy gateway to downstream server, with a JSONL trace">
</picture>

On a 47 case corpus the gateway catches 25 of 26 attacks and wrongly blocks 2 of 21
legitimate calls. A keyword filter, the alternative teams actually reach for, catches 10
and blocks 7. Every number here is reproduced by `python evaluation/benchmark.py`.

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

## Results

Deterministic. 47 cases, no model calls, no network. `python evaluation/benchmark.py`
reproduces every rate in this table exactly on any machine. The decision-time column is
the exception: it is a property of the machine it ran on, not of the system, and it moves
by tens of microseconds between runs.

| Configuration | Attacks caught | Benign refused | Benign untouched | Median decision |
|---|---|---|---|---|
| **baseline** (no gateway) | 0.0% | 0.0% | 100.0% | 0 µs |
| **keyword filter** | 38.5% | 33.3% | 66.7% | 5 µs |
| **gateway** | **96.2%** | **9.5%** | 76.2% | 249 µs |

![What each option costs](docs/figures/01_tradeoff.png)

The keyword filter is in there because it is the real alternative. "We added a filter" is
what actually happens when a team decides to do something about prompt injection, and
comparing only against *nothing* would flatter the result. It catches a third of the
attacks and refuses one in three legitimate calls, which is the profile of a control that
gets switched off in week two.

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

Per control, on the same run:

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
were.

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
| MCPTox, after the two changes it prompted | **39.8%** | [35.5%, 44.2%] |

The first number is the useful one. `mandatory_tool_precondition` bounded the gap between
"before" and the obligation at 40 characters, which fits how *I* write a case and not how
anyone else does; 72 of the 103 missed declarations carrying that pair exceeded it. A second
attack class — a declaration claiming priority over the user, then coercing an argument
value — had no rule at all. Neither could have been found on 47 cases of mine.

The internal numbers did not move through either change, including the benign cases that
caused that rule to be narrowed in the first place.

The benign half is external too, because recall without a false-positive rate is the shape
of result this project criticises the keyword filter for. Scored against **660 real tool
declarations** — harvested from the official MCP reference servers and from MCP-Guard's
benign set — the gateway blocks **0** and touches **0**, interval [0.0%, 0.6%].

That includes the `fetch` server's own description, which tells the model it was "advised to
refuse and tell the user this" and that it may now do otherwise. Official prose with the
shape of an injection, and it passes.

**39.8% should not be read as generalisation.** Most of the gain is one rule, and the phrase
it keys on appears in 0% of their first two generators and 35% of the third. It is one
generator's opening sentence. 292 of 485 are still missed and the three generators disagree
at 29.9%, 44.8% and 39.1%. These rates also are not comparable to the ones in their paper:
MCPTox scores whether a *model complies*, this scores whether a *control fires*.

Nothing of theirs is redistributed here — they publish no licence, so the corpus is pinned
by commit and digest and fetched at evaluation time. `make check` and `make bench` stay
offline.

```bash
make bench-external     # fetches once, then deterministic
```

Full write-up, including what it does not establish, in
[`docs/learning/08_external_validation.md`](docs/learning/08_external_validation.md).

## Run it

```bash
python -m venv .venv && . .venv/Scripts/activate     # or bin/activate
pip install -e ".[dev]"

python -m mcp_policy_gateway.cli demo                # real MCP process, real stdio
python evaluation/benchmark.py                       # the table above
pytest                                               # the test suite
```

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

## Documentation

`docs/learning/` works from the problem up: what MCP is and why its trust boundary is
unusual, the threat model, the architecture, the implementation, how the evaluation is
constructed, where it fails, and what to try next.

## Licence

MIT. See [`LICENSE`](LICENSE).
