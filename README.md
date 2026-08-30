# mcp-policy-gateway

Runtime policy enforcement for Model Context Protocol tool calls, and a deterministic
benchmark that measures which controls actually stop which attacks.

## The problem

An MCP client hands a model a set of tools, calls them on the model's behalf, and feeds
the results back into context. Three things in that loop are untrusted, and they are
untrusted at different times:

1. **Tool declarations.** A server describes its own tools. A description is prose that
   most clients concatenate into a prompt, so a server can put instructions there.
2. **Call arguments.** Built by a model from a schema, then sent to a server that may or
   may not validate them.
3. **Tool results.** Whatever comes back is read into context. It is a document, a search
   result, a database row — content the server did not write and cannot vouch for.

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

```
  client  ──MCP──▶  policy gateway  ──MCP──▶  downstream server
                    │
                    ├─ discovery : inspect declarations before the client sees them
                    ├─ request   : inspect arguments before the call is forwarded
                    └─ response  : inspect results before they re-enter context
                    │
                    └─▶ trace (JSONL): decision, rules, timing, payload digests
```

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
the strongest action wins — allow, sanitise, hold for approval, or block.

## Results

Deterministic. 44 cases, no model calls, no network. `python evaluation/benchmark.py`
reproduces this table exactly on any machine.

| Configuration | Attacks caught | Benign refused | Benign untouched | Median decision |
|---|---|---|---|---|
| **baseline** (no gateway) | 0.0% | 0.0% | 100.0% | 0 µs |
| **keyword filter** | 38.5% | 38.9% | 61.1% | 3 µs |
| **gateway** | **92.3%** | **11.1%** | 77.8% | 117 µs |

The keyword filter is in there because it is the real alternative. "We added a filter" is
what actually happens when a team decides to do something about prompt injection, and
comparing only against *nothing* would flatter the result. It catches a third of the
attacks and refuses two out of five legitimate calls, which is the profile of a control
that gets switched off in week two.

Per control, on the same run:

| Control | Attacks caught | Benign cases touched |
|---|---|---|
| `instruction_injection` | 15 | 4 |
| `egress_control` | 4 | 0 |
| `path_sandbox` | 4 | 0 |
| `secret_disclosure` | 3 | 0 |
| `schema_conformance` | 2 | 0 |
| `tool_allowlist` | 2 | 0 |
| `tool_shadowing` | 1 | 0 |
| `destructive_action` | 1 | 0 |
| `budget` | 1 | 0 |

Every benign case that gets touched is touched by the one control that has to make a
judgement call. The eight deterministic controls have no false positives on this corpus,
which is the argument for keeping the judgement in exactly one place.

## Where it fails

Four cases out of 44 are not handled, and all four were written before the controls were.

| Case | What it is | Why it fails |
|---|---|---|
| `inject-006` | Base64 of an override instruction, no plaintext around it | Matching runs on the raw text. Decoding every base64-looking span before matching would flag legitimate encoded attachments, so this is a deliberate open gap, not an oversight. |
| `secret-004` | A bare 64-hex-character credential | Catching it means flagging every SHA-256 digest in every document. The control keys on prefixes and assignment shape instead. |
| `fp-known-001` | A runbook saying "ignore the previous instructions in section 3" | Genuine operator prose with the exact shape of an attack. There is no signal available that separates them. |
| `fp-known-002` | Onboarding text asking someone to "show your system prompt" | Same problem. Internal documentation discusses prompts now. |

The two false positives are the honest cost of the injection control, and they are the
reason it is the only control allowed to be uncertain. Full write-up in
[`docs/learning/06_failures.md`](docs/learning/06_failures.md).

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
- **A corpus with ground truth per case.** 26 attacks, 18 benign near-misses. Each case
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

## Documentation

`docs/learning/` works from the problem up: what MCP is and why its trust boundary is
unusual, the threat model, the architecture, the implementation, how the evaluation is
constructed, where it fails, and what to try next.

## Licence

MIT. See [`LICENSE`](LICENSE).
