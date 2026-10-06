# 9. What this gateway cannot see

Section 8 reports how well the controls do on attacks they can see. It says nothing about
the attacks they cannot, and no recall number ever will: a percentage over a corpus of tool
poisoning tells you about tool poisoning, and is silent about the other sixteen things on
the published list.

So this is the other half of the picture, and the rows worth reading are the ones that do
not say "covered".

## 9.1 Whose taxonomy

MCPSecBench (arXiv:2508.13220) enumerates 17 attack types across four surfaces. It is used
here because it was assembled by people describing the protocol rather than by me
describing my own gateway - a taxonomy of my own would be drawn around whatever happens to
be implemented, and would mark itself complete.

Their data is not usable here and section 8.1 says why: eleven prompts aimed at a live
host, scored by whether Claude Desktop complied, which is a question about a model and not
about a protocol-boundary control. The taxonomy is a different artefact and it is sound.

The map is `evaluation/coverage.py` rather than this prose, and `python -m
evaluation.coverage` prints it. Tests hold it to the 17 vectors, to the four surface
counts, and to the control set in both directions: a control named here must exist, and a
control that exists must be placed somewhere here. A map that can go quietly out of date is
worse than no map.

## 9.2 The map

| Surface | Vector | | Controls |
|---|---|---|---|
| User Interaction | Prompt Injection | out of scope here | - |
| User Interaction | Tool/Service Misuse via "Confused AI" | covered | `tool_allowlist`, `destructive_action` |
| User Interaction | Indirect Prompt Injection | covered | `instruction_injection`, `budget` |
| MCP Client/Endpoint | Schema Inconsistencies | covered | `schema_conformance` |
| MCP Client/Endpoint | Slash Command Overlap | out of scope here | - |
| MCP Client/Endpoint | Vulnerable Client | out of scope here | - |
| MCP Transport | MCP Rebinding | out of scope here | - |
| MCP Transport | Man-in-the-Middle | out of scope here | - |
| MCP Server | Tool Poisoning Attack | covered | `instruction_injection` |
| MCP Server | Tool Shadowing Attack | covered | `tool_shadowing` |
| MCP Server | Data Exfiltration | covered | `secret_disclosure`, `egress_control` |
| MCP Server | Package Name Squatting (tool name) | covered | `tool_shadowing`, `tool_allowlist` |
| MCP Server | Sandbox Escape | covered | `path_sandbox` |
| MCP Server | Package Name Squatting (server name) | **visible, uncovered** | - |
| MCP Server | Configuration Drift | **visible, uncovered** | - |
| MCP Server | Rug Pull Attack | **visible, uncovered** | - |
| MCP Server | Vulnerable Server | out of scope here | - |

| | count |
|---|---|
| covered | 8 |
| visible, uncovered | 3 |
| out of scope at this position | 6 |

## 9.3 Out of scope is a claim about position, not an excuse

Six vectors are unreachable from here, and that is a property of where the gateway sits
rather than of how much work has gone into it. It fronts a server and speaks MCP on both
sides, so it sees declarations, arguments and results. It does not see the user's prompt,
the client's internals, or the transport underneath.

Direct prompt injection happens above it. Slash command overlap is resolved inside the host
before anything becomes MCP traffic. A vulnerable client is upstream and can decline to use
the gateway at all. Rebinding and man-in-the-middle are won or lost below the protocol, in
name resolution and in TLS. A vulnerable server is code the gateway never sees; it can
narrow what reaches it, which is not the same as assessing it.

Naming these as structural matters in both directions. It stops the gateway being credited
with coverage it does not have, and it stops the uncovered list being padded with things no
control placed here could ever address.

## 9.4 The three that are the roadmap

Package name squatting by server name, configuration drift, and rug pull are all visible
from this position and none is addressed. They are also, between them, a single missing
capability: **nothing here remembers what a server declared last time.**

Every control is a pure function of one event and its context, which section 3 argues for
at length - it is what makes each one independently testable and what makes per-control
effectiveness measurable at all. The cost of that choice shows up exactly here. A tool
definition that was benign on Monday and hostile on Friday is two independent evaluations,
both correct, and the change between them - which is the attack - is not an input to
either.

Rug pull is the sharpest case because the attack *is* the change. A server behaves until it
is trusted and then alters what it declares, and there is no single event at which anything
is wrong.

Closing those three means holding declaration state across sessions and comparing against
it. That is a real design change rather than another rule, it would be the first stateful
thing in the control set apart from the budget counter, and it is not attempted here.

## 9.5 What this section does not establish

The verdicts are reasoned, not measured. "Covered" means a control exists whose job is that
vector, and section 8 measures how well exactly one of them does against an external
corpus: tool poisoning, at 49.5%. Covered is not a score, and nothing here should be read
as one.
