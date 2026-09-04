# 7. Experiments and what to try next

Things measured along the way, and things worth doing that are not done.

## 7.1 Does context demotion actually help?

The injection control demotes a finding from BLOCK to SANITISE when the match sits in a
quote, a fenced block, or after reporting language. That is a design claim, so it is
switchable and measurable rather than asserted:

```python
InstructionInjection(demote_when_framed=False)
```

With demotion **off**, `ok-advisory-001` and `ok-advisory-002`, a security advisory and a
detection rule under review, are refused outright. With it on, they pass with the quoted
span redacted, and no attack case changes verdict.

The mechanism is pinned by `test_reporting_context_demotes_rather_than_blocks` and
`test_demotion_can_be_disabled_for_measurement`.

**Caveat.** Demotion is an attack surface: text framed to look like reporting gets a
weaker response. The corpus does not currently contain an attack that exploits this
deliberately, which is the most obvious gap to close next (§7.5).

## 7.2 Cost of the boundary

Median decision time, measured in the benchmark:

| Configuration | Median |
|---|---|
| baseline | 0 µs |
| keyword | 3 µs |
| gateway | ~100 µs |

Roughly 100 microseconds per event, three events per tool call, so about 0.3 ms of policy
per call. Against a tool call that touches a disk or a network, units of milliseconds at
best, this is not a number worth optimising.

The design deliberately spends some of it: every control runs on every event even after
one has blocked, which costs microseconds on already-refused calls and buys per-control
attribution that is not an artefact of ordering.

## 7.3 The withheld-tool gap

Found by the integration tests, not the corpus. The gateway hid a poisoned tool at
discovery and then executed a direct call to it: hiding a name from a listing is not the
same as making it uncallable, and the request-stage controls have no idea the declaration
was rejected because they only see the call.

Worth recording because it is the class of bug a policy corpus structurally cannot find.
The corpus tests decisions; this was a bug in *wiring*.

## 7.4 Rejected: LLM-as-judge

Considered and not built. Reasoning in [`05_evaluation.md`](05_evaluation.md) §5.6:
determinism, reproducibility and CI cost, plus the principle that a probabilistic judge
should not replace a decidable check.

The version worth building is **hybrid**: patterns at the boundary for the cheap certain
cases, a model only for text that no rule fired on and that is about to enter context.
That keeps the common path deterministic and free, and spends a model call only on the
ambiguous remainder. It needs a way to evaluate the judge that does not itself depend on
the judge, which is the hard part.

## 7.5 Next, roughly in order of value

**A paraphrase set.** The single most important gap. Generate rephrasings of each
injection case and measure how fast recall falls off. The 92.3% figure is against the
attack forms represented; a paraphrase axis would put a number on how much that
over-states things.

**Attacks that exploit demotion.** Payloads deliberately framed as quotation or reporting,
to measure the cost of §7.1's trade rather than assuming it is small.

**Multi-turn assembly.** Instructions split across several tool results. Needs a control
with a window over the session, which no current control has.

**A real downstream server.** The demo uses a purpose-built hostile server. Running the
gateway in front of the official filesystem or fetch servers, with a corpus of documents
on disk, would test the proxy against a server that was not written to be tested.

**Approval as a protocol.** `REQUIRE_APPROVAL` currently returns a refusal that names the
reason. A real deployment needs a way to *grant* approval and resume, an elicitation
round-trip, which MCP 2.x supports and this does not use yet.

**Independent evaluation.** The corpus is mine, and that is the standard weakness of a
self-built benchmark (§6.6). Scoring against a corpus somebody else wrote, or having
someone try to get a payload past it, would be worth more than any additional rule.

## 7.6 What I would tell someone starting this

Three things that were not obvious at the start:

1. **The benign half is the hard half.** I expected to spend the time writing attacks.
   Almost all the difficulty was in the near-misses, and they are what forced every
   interesting design decision, shape over vocabulary, four actions instead of two,
   demotion, skipping unknown schema keywords.

2. **Keep uncertainty in one place.** Eight controls with decidable answers and one that
   guesses is a much better structure than nine that all guess a little. It means the
   false-positive story has exactly one owner, and the per-control table shows that
   directly.

3. **Measure the strawman.** The keyword filter is what a team actually builds. Without
   it in the table, "92.3% caught" sounds impressive and says nothing about whether the
   extra machinery was worth writing. With it, the interesting number is not the recall, it is the 38.9% false-block rate that the extra machinery removes.
