# External validation: scoring the gateway on a corpus I did not write

Design document. All four stages are done: the results are in
[§8](../learning/08_external_validation.md) and the coverage map in
[§9](../learning/09_coverage.md).

§6.6 and §7.5 both end at the same place: the corpus is mine, I wrote both the attacks and
the controls, and no amount of care inside that loop substitutes for being scored by
someone else. §7.5 puts it plainly — scoring against a corpus somebody else wrote "would
be worth more than any additional rule". This is the plan for doing that.

The result that matters is not a better number. It is a number produced by cases this
repository did not choose, reported whatever it turns out to be.

## 1. What this measures, and what it cannot

The gateway currently reports 96.2% caught [81.1%, 99.3%] on 26 attacks I wrote. The
interval covers sampling error: how much that rate moves on another 26 cases *written the
same way*. It says nothing about cases written a different way, by someone with different
intuitions about what an attack looks like.

That second quantity is what external validation estimates. The distinction is the whole
point of the exercise, so it is worth being exact about it:

| Quantity | Estimated by | Currently |
|---|---|---|
| Rate on more cases like mine | internal corpus + Wilson | reported |
| Rate on cases somebody else wrote | external corpus | **not reported** |
| Rate on real traffic | neither | out of reach, stays out of reach |

The third row does not become available at the end of this work. An external academic
corpus is still a corpus: assembled deliberately, to make a point, by people studying the
problem rather than attacking anyone. Moving from "my cases" to "their cases" narrows one
specific gap and leaves the deployment question open.

## 2. Sources

### 2.1 Attacks — MCPTox

MCPTox (AAAI 2026, *A Benchmark for Tool Poisoning Attack on Real-World MCP Servers*) is
built on live MCP servers and authentic tools. The paper reports 1,348 malicious cases; the
published `pure_tool.json` holds **485 poisoned tool records across 45 servers**, and 485 is
what this plan is sized against. The gap is not explained in their repository, so the
write-up states what was actually scored rather than what the paper counts.

Each record carries `server_name`, `tool_name`, `tool_address`, `query`, `tool_content`, and
two label fields:

| Field | Values | Use here |
|---|---|---|
| `security risk` | 11 categories, from Information Manipulation (108) down to Other (2) | per-category recall, their vocabulary not mine |
| `paradigm` | Template-1 (77), Template-2 (183), Template-3 (225) | whether recall is a property of the attack or of the generator |

It fits because tool poisoning is *instructions embedded in tool metadata at registration*,
which is exactly the gateway's DISCOVERY stage. `tool_content` holds the poisoned
description, the same object the `instruction_injection` and `tool_shadowing` controls
already read.

The `paradigm` split is worth keeping in view. Three templates generated all 485 cases, so
the cases are not independent in the way 485 separately-written attacks would be. A Wilson
interval on 485 will look tight and will overstate what is known: it measures sampling
within three templates. Per-template recall is therefore reported alongside the pooled
figure, and if the three disagree the pooled number is the less meaningful one.

At 485 against the internal 26, the comparison is still worth having. It is simply a
different quantity from "485 independent attacks", and must be labelled as one.

Its payloads are recognisably the same family as `poison-001` without being the same cases,
which is the useful relationship: close enough that the controls are in scope, independent
enough that passing is informative.

### 2.2 Benign — the official MCP reference servers

MCPTox is attacks only. Scoring recall without a benign half would measure the less
interesting direction; §7.6 already records that the benign half is the hard half.

The reference servers at `modelcontextprotocol/servers` — `everything`, `fetch`,
`filesystem`, `git`, `memory`, `sequentialthinking`, `time` — declare real tools, written to
be used rather than to be tested, by people who had never heard of this gateway. That is a
stronger benign set than anything I would write next, for the reason §7.5 gives when it asks
for a real downstream server.

Any false positive here is unambiguous. There is no argument available that the declaration
was really a bit suspicious.

### 2.3 Taxonomy — MCPSecBench

MCPSecBench (arXiv 2508.13220, MIT) enumerates 17 attack vectors across the MCP surface.
Its *data* is not usable here: eleven prompts aimed at a live host, scored by whether Claude
Desktop or Cursor complied. That is an end-to-end question about a model, not a question
about a protocol-boundary control, and treating one as the other would be a category error.

Its *taxonomy* is usable, and is the thing worth taking. Mapping the nine controls onto 17
independently-chosen vectors answers a question this repository cannot currently answer:
which parts of the published attack surface a gateway at this position can see at all, as
distinct from which it catches. Vectors that are structurally invisible here — a vulnerable
client, a rebinding attack, a compromised transport — should be named as out of scope rather
than quietly scored as misses.

## 3. Constraints

### 3.1 Neither external corpus carries a license

`zhiqiangwang4/MCPTox-Benchmark` and `GenTelLab/MCP-Guard` publish no `LICENSE`, so default
copyright applies and no redistribution right is granted. MCPSecBench is MIT; the reference
servers repository reports `NOASSERTION` and needs checking per file before anything is
copied.

This repository therefore **vendors none of it**. The external corpus is fetched at
evaluation time into a gitignored cache, pinned by commit SHA and verified by content hash.
What gets committed is the pin, the hash, the adapter, and the results — never the payloads.

A reader who wants to reproduce the run fetches it themselves from the original source,
which is also the correct way to be cited.

### 3.2 The offline guarantee is load-bearing

The Makefile promises that everything runs offline: no API key, no network, no GPU. That is
a real property of `evaluation/benchmark.py` and it is why the headline numbers reproduce
byte-for-byte on any machine.

External evaluation needs the network, and must not be allowed to erode that. It lives in
its own module behind its own target, and `make check` and `make bench` continue to run with
the network unplugged. A fetch failure must never be able to change the internal numbers;
the two paths share the scoring helpers and nothing else.

### 3.3 No new dependencies

The only runtime dependency is `mcp`, and `wilson()` is hand-rolled rather than imported
from scipy. The extension holds that line: `urllib`, `json`, `hashlib`, `pathlib` from the
standard library, and the existing `wilson()` for intervals.

## 4. The reduction, stated plainly

MCPTox scores whether a *model complies* with a poisoned tool. The gateway asks whether a
*control fires* on it. These are different questions and the second is not a proxy for the
first.

The mapping used here is: a declaration MCPTox labels poisoned should be met with BLOCK or
SANITISE at DISCOVERY; anything else counts as a miss.

That is defensible — their ground truth is the claim that the declaration is malicious,
which is a property of the declaration — but it is a reinterpretation of their labels under
a different question, and every published number must say so. Reporting it as "the gateway
scores X on MCPTox" without that sentence would be the overclaiming this repository was
written to avoid, and would also misrepresent their work.

Specifically, these numbers are **not comparable to the attack success rates in their
paper** and must never be placed in a table beside them.

## 5. Shape

```
evaluation/external/
  __init__.py
  sources.py     pinned SHAs, expected content hashes, citations
  fetch.py       download into .cache/external/, verify hash, fail loudly
  adapt.py       MCPTox record            -> discovery event + expected action
  harvest.py     reference server sources -> discovery events, expected allow
  score.py       run the engine unchanged, report with Wilson intervals
```

`score.py` imports the engine and `wilson()` and adds no scoring logic of its own. If the
external harness needs a behaviour the internal benchmark does not have, that is a signal
the comparison is drifting and the difference gets written down rather than coded around.

Caching: `.cache/external/` is gitignored. `fetch.py` refuses to proceed on a hash mismatch
rather than silently re-pinning, because a corpus that changes underneath a published number
is the failure mode this repository already guards against at 1e-9 elsewhere.

## 6. Stages

Each stage lands on its own, and each produces a number that can be reported even if the
next is never done.

**Stage 1 — recall on MCPTox.** Pin, fetch, adapt, score the 485 attack records. Produces
external recall with a Wilson interval, a per-control attribution table alongside the
internal one, recall per `security risk` category, and recall per `paradigm` template. The
per-template split is not optional: it is what distinguishes a result about tool poisoning
from a result about three generators. This is the stage that answers the §7.5 question.

**Stage 2 — false positives on real tools.** Harvest declarations from the reference
servers, score, report the external false-positive rate. Expected to be the more
uncomfortable half, since §6.5 already keeps two known false positives on operator prose and
real tool descriptions are prose.

**Stage 3 — coverage against the MCPSecBench taxonomy.** Map nine controls onto 17 vectors.
Three outcomes per vector: covered, structurally out of scope at this position, or visible
but uncovered. The third list is the honest roadmap.

**Stage 4 — write-up.** `docs/learning/08_external_validation.md` in the existing series,
and a README section. If external recall is materially below 96.2%, the README leads with
that rather than burying it, and the internal number is relabelled as what it always was: an
in-distribution result.

## 7. What would make this a failure

Worth fixing in advance, because each has an obvious tempting response:

- **Adapter tuning.** If the adapter is adjusted until the score improves, it has become
  part of the system under test. The adapter is written once against the data format, before
  any score is seen, and changes to it after that point are recorded in the write-up with
  the before and after.
- **Quiet dropping.** Cases that do not map cleanly get counted and reported as unmapped,
  never silently skipped. An unmapped rate is itself a finding about the controls' reach.
- **Reporting only the good half.** Stage 1 and Stage 2 are published together or not at
  all. Recall without the false-positive rate is the shape of result this repository
  criticises the keyword filter for.
- **Burying a bad number.** The point of the exercise is that the number is not mine to
  choose.

## 8. What success looks like

Not a high score. A number from cases I did not write, with an interval, next to the
internal number, with the gap between them explained and the reduction that produced it
stated. If the gateway holds up, that is worth more than 96.2% on home ground. If it does
not, that is worth more still, and it is the only way to find out before someone else does.
