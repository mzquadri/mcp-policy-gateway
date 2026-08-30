# 1. The problem

## What MCP is

The Model Context Protocol is a wire format that lets a language-model client use tools
provided by a separate process. A *server* advertises tools; a *client* lists them, picks
one, sends arguments, and gets a result back. It is JSON-RPC over stdio or HTTP, and the
interesting part is not the transport — it is who is trusted.

A minimal exchange:

```
client → server   initialize
client → server   tools/list
server → client   [ { name: "read_file", description: "Reads a file.", inputSchema: {...} } ]
client → server   tools/call  { name: "read_file", arguments: { path: "notes.txt" } }
server → client   { content: [ { type: "text", text: "..." } ] }
```

Four messages, and three of them carry text that ends up inside a model's context window.

## Why the trust boundary is unusual

In an ordinary API integration, the danger is that *your* code sends bad input to
*their* server. The data flows one way and the parser on the far side is the thing you
worry about.

Here the danger runs the other way, and it is not a parsing problem. Everything the
server sends is **prose that a model reads and may act on**. A tool description is not a
docstring the way a docstring is in Python — the client concatenates it into the prompt so
the model knows what the tool does. A tool result is not a return value the model
inspects at arm's length — it is appended to the conversation.

So the server can write sentences into the model's context, and a model has no reliable
way to tell a sentence that describes data from a sentence that instructs it. That is the
whole vulnerability class, and it has a name: **prompt injection**. The MCP-specific
variants have their own names:

- **Tool poisoning.** Instructions hidden in a tool's *description*, which the client
  reads once at discovery and puts in the prompt.
- **Tool shadowing.** A second server declaring a tool name a first server already owns,
  so the client routes calls to the wrong place.
- **Indirect prompt injection.** Instructions inside a tool's *result* — in a document the
  server returned, which the server did not write and cannot vouch for.

## The three untrusted moments

Once you list them out, it is clear they happen at different times and need different
answers.

| Moment | What arrives | Who wrote it | When it can be checked |
|---|---|---|---|
| Discovery | Tool names, descriptions, schemas | The server author | Once, before any call |
| Request | Arguments | The model, from the schema | Before forwarding |
| Response | Result content | Whoever wrote the underlying data | Only after the call runs |

The third row is the one that matters most and gets the least attention. The document
containing the injection did not exist when you scanned the server. It might have been
uploaded five minutes ago by someone who is not the server author and is not you.

## What already exists

The security tooling for MCP is largely **static scanners**: point them at a server, they
read the declarations and flag suspicious ones. [Snyk
`agent-scan`](https://github.com/snyk/agent-scan) and similar tools do this well.

Scanning declarations is genuinely useful and it covers exactly one of the three rows. It
cannot cover the third, not because the tools are weak but because of *when* they run:
there is nothing to scan yet.

## What this project asks

> If you put an enforcement point at the protocol boundary, where all three moments are
> visible, how much does each control actually buy — and what does it cost in false
> refusals?

Two halves, and the second is the one people skip. A control that blocks every attack and
also refuses one in three legitimate calls gets switched off in week two, at which point
its real-world effectiveness is zero. So the measurement here always reports both:

- **caught** — share of attacks handled
- **false block** — share of legitimate traffic refused

and the corpus is built so the second number is hard to get right. See
[`05_evaluation.md`](05_evaluation.md).

## What this project is not

- **Not a model-based defence.** No classifier, no LLM-as-judge. Every decision is a
  deterministic function of the text, so the benchmark reproduces exactly and CI needs no
  API key. That is a real limitation as well as a feature; see
  [`06_failures.md`](06_failures.md).
- **Not a replacement for the scanner.** They occupy different moments. Running both is
  the sensible position.
- **Not a claim that prompt injection is solved.** It is not, and a pattern-matching
  gateway will not be what solves it. The claim is narrower: a boundary with nine
  controls catches 92% of a representative corpus while refusing 11% of near-miss benign
  traffic, and here is the corpus so you can disagree.

Next: [`02_foundations.md`](02_foundations.md) — the concepts and vocabulary.
