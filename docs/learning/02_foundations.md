# 2. Foundations

The concepts this project assumes, from the bottom. If you already know what a
confused-deputy problem is, skip to §2.5.

## 2.1 Prompt injection, precisely

A language model receives one sequence of tokens. Instructions from the developer, the
user's question, and data fetched from elsewhere all arrive in the same channel. There is
no bit that marks a token as *data* rather than *instruction*, the separation is a
convention the model learned, not a property of the input.

Prompt injection is what happens when text that was supposed to be data is written so it
reads as instruction. It is the same shape as SQL injection, with one difference that
matters enormously:

| | SQL injection | Prompt injection |
|---|---|---|
| Cause | Data concatenated into a command string | Data concatenated into a prompt |
| Fix | Parameterised queries, a real channel separation | **No equivalent exists** |
| Why | The parser can be told which bytes are data | The model has one channel by construction |

There is no `PreparedStatement` for a prompt. Delimiters help and can be forged; system
prompts help and can be argued with. This is why defences are mitigations rather than
fixes, and why measuring them matters more than asserting them.

**Direct** injection is the user typing it. **Indirect** injection is the interesting
one: it arrives in content the system fetched, a document, a web page, a search result.
The user never sees it, and the person who wrote it may have planted it months earlier.

## 2.2 The confused deputy

An old idea from capability security, and the cleanest way to see why an agent is
dangerous.

A *deputy* acts on behalf of a principal and holds authority of its own. It becomes
*confused* when it is tricked into using its authority for someone else's purposes.

An MCP agent is a textbook deputy. It holds your filesystem access, your API tokens, your
database credentials. A document it reads can tell it what to do. The document has no
authority; the agent has all of it; and the agent cannot reliably tell the difference
between its principal's instruction and a sentence in a file.

This reframes the defence. You are not trying to make the model resistant to persuasion, that is a model-training problem and not one a proxy can solve. You are trying to ensure
the deputy's *authority is small enough* that being confused is survivable. That is what
allowlists, sandboxes, budgets and approval gates are for, and it is why this project has
eight boring controls and only one clever one.

## 2.3 Defence in depth, and why per-control numbers matter

Layered defence is the standard answer. The trap is that "we have nine controls" is not a
statement about security, nine controls that all catch the same thing are one control.

So the effectiveness table here reports controls independently: every control runs on
every event, even after another has already blocked it. That costs a few microseconds and
buys the ability to answer "what does *this one* catch", which you cannot answer if
controls short-circuit each other. See [`03_architecture.md`](03_architecture.md).

## 2.4 Precision and recall, in this setting

Standard classification vocabulary, mapped onto the problem.

- **True positive**, an attack the gateway handled.
- **False negative (miss)**, an attack that got through.
- **False positive (false block)**, legitimate traffic refused.
- **True negative**, legitimate traffic passed.

**Recall** = TP / (TP + FN), the share of attacks caught. Reported as `caught`.

**Precision** = TP / (TP + FP), of everything flagged, how much was really an attack.

This project foregrounds recall and the **false block rate** rather than precision,
because false block is the number that predicts whether the control survives. An operator
does not experience precision; they experience a refused document.

There is a structural asymmetry worth stating. A miss is a possible incident. A false
block is a certain, immediate, visible cost to a user. Teams under-weight the second
because it does not have a CVE number, and then quietly disable the control. Weighting
them equally in the report is a deliberate choice.

## 2.5 Why not a model-based classifier

The obvious alternative to regular expressions is a small classifier, or asking a model
"is this an injection?". Both are legitimate and both were rejected here, for reasons
worth writing down:

| | Patterns (chosen) | Model-based |
|---|---|---|
| Determinism | Same input, same answer, forever | Varies by version, temperature, provider |
| Reproducibility | CI runs it with no key | Needs credentials and money |
| Latency | ~100 µs | 100–1000 ms per call |
| Explainability | Names the rule and the span | "The classifier said 0.87" |
| Evasion | Rephrasing defeats it | Harder to evade by rephrasing |
| Coverage of novelty | Poor, only known shapes | Better |

The last row is a real loss and it is not hidden: a paraphrased attack that avoids every
pattern gets through, and `inject-006` in the corpus is exactly that case, kept as a
scored miss.

The trade was made for the first three rows. A security control that cannot be re-run
deterministically cannot be regression-tested, and one that costs a model call per tool
result changes the economics of every agent that uses it. A production deployment would
sensibly run both, patterns at the boundary for the cheap certain cases, a model for the
ambiguous remainder. That is written up in [`07_experiments.md`](07_experiments.md).

## 2.6 Repositories reviewed during selection

Read for architecture and threat vocabulary. None contributed code; see `NOTICE`.

| Repository | Licence | What it does | Why it was read |
|---|---|---|---|
| `modelcontextprotocol/python-sdk` | MIT | The protocol SDK | Used as a dependency. Targets 2.x, where `FastMCP` became `MCPServer`. |
| `snyk/agent-scan` | Apache-2.0 | Static scanner for MCP servers and skills | The reference example of the pre-execution approach this measures against |
| `sierra-research/tau2-bench` | MIT | Tool-agent-user benchmark | Benchmark construction; rejected as an upstream because it needs paid model calls |
| `Arize-ai/phoenix` | Elastic-2.0 | Trace/eval platform | Trace schema shape. Licence is not permissive, so read only |
| `langfuse/langfuse` | MIT core + EE | Self-hosted LLM tracing | Same |
| `comet-ml/opik` | Apache-2.0 | Observability and evaluation | Same |
| `confident-ai/deepeval` | Apache-2.0 | LLM evaluation framework | Metric design |
| `illuin-tech/colpali` | MIT | Visual document retrieval | Considered as a different project direction |
| `AgentOps-AI/agentops` | MIT | Agent session tracking | Session/trace modelling |
| `openai/evals` | MIT-ish (`NOASSERTION`) | Eval harness | Corpus/ground-truth conventions |
| `eSentire-Labs/mcp-scanner` | **none** | MCP vulnerability scanner | **Rejected: no licence file, so it cannot be used or adapted** |
| OWASP MCP Tool Poisoning | Docs | Threat taxonomy | Source of the attack-class names used in `corpus/` |

Next: [`03_architecture.md`](03_architecture.md).
