# 5. Evaluation

## 5.1 What is being measured

Not "does the gateway catch things" — it was written against this corpus, so of course it
does. The question is what it costs, and whether it beats the thing a team would actually
build instead.

Three configurations:

| Configuration | What it is | Why it is here |
|---|---|---|
| `baseline` | No gateway. Every call proceeds. | What an MCP client does today. |
| `keyword` | Substring matching on obvious phrases. | **The real alternative.** "We added a filter" is what happens when a team decides to do something. |
| `gateway` | All nine controls. | The thing being evaluated. |

Including `keyword` is the part that keeps the result honest. Comparing only against
*nothing* flatters any filter; comparing against the strawman that a competent engineer
would write in an afternoon is the comparison that says whether the extra machinery earns
its place.

## 5.2 The corpus

44 cases: **26 attacks, 18 benign**. Python data rather than YAML, because every case
carries a `rationale` and a rationale is only useful next to the payload it explains.

Attack classes:

| Class | Cases | Stage |
|---|---|---|
| `tool_poisoning` | 3 | discovery |
| `tool_shadowing` | 1 | discovery |
| `indirect_prompt_injection` | 6 | response |
| `path_traversal` | 4 | request |
| `secret_exfiltration` | 4 | request, response |
| `egress_violation` | 2 | request |
| `schema_violation` | 2 | request |
| `unlisted_tool` | 2 | request |
| `destructive_action` | 1 | request |
| `resource_exhaustion` | 1 | response |

## 5.3 Ground truth is per case, not per class

The tempting rule is "attacks must be blocked". It is wrong for a whole family of them: a
credential inside an otherwise legitimate document should be *redacted*, because refusing
throws away the document too.

So each case declares the boundary it cares about:

- **attack → `expected` is the weakest acceptable response.** `SANITISE` means
  neutralising is enough; `BLOCK` means the call must not proceed.
- **benign → `expected` is the strongest acceptable response.** `ALLOW` means touching it
  at all is a false positive; `SANITISE` means redaction is tolerable, refusal is not.

In code:

```python
def handled(case, decision):
    if case.is_attack:
        return decision.action.severity >= case.expected.severity
    return decision.action.severity <= case.expected.severity
```

The asymmetry is the point, and `test_handled_semantics_are_asymmetric` pins it.

## 5.4 The benign half is the hard half

A benign set of unrelated prose proves nothing — every filter passes it, and a gateway
scored only against that looks perfect while being unusable.

Every benign case here is a **near-miss**, built to be the thing a careless rule breaks:

| Case | The trap |
|---|---|
| `ok-advisory-001` | A security advisory quoting "ignore all previous instructions" |
| `ok-advisory-002` | The same payload inside a fenced code block |
| `ok-advisory-003` | "disregard the earlier draft" — right verb, wrong object |
| `ok-doc-001` | "Before using ... you must install" — precondition shape, human audience |
| `ok-doc-003` | "Do not tell the reader" — concealment shape, non-user object |
| `ok-path-002` | `reports/../archive/q2.txt` — contains `..`, normalises inside |
| `ok-path-003` | `notes/..hidden/summary.txt` — dots in a filename |
| `ok-egress-001` | The legitimate mirror of the suffix-confusion attack |
| `ok-tool-002` | An honest description that reads a bit like an instruction |
| `ok-tool-003` | The same server re-declaring its own tool |
| `ok-destruct-001` | The destructive call, with approval recorded |

## 5.5 Results

```
corpus: 26 attack cases, 18 benign cases

configuration    caught   false block   clean pass    median
baseline          0.0%          0.0%       100.0%        0us
keyword          38.5%         38.9%        61.1%        3us
gateway          92.3%         11.1%        77.8%       98us
```

The keyword filter catches **a third of the attacks and refuses two out of five
legitimate calls**. That is the profile of a control that gets switched off, and it is
why the comparison is in the report.

Per control:

| Control | Attacks caught | Benign touched |
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

**Every false positive comes from the one control that has to make a judgement.** The
eight deterministic controls have none on this corpus. That is the argument for keeping
uncertainty in exactly one place, and `test_deterministic_controls_have_no_false_positives`
enforces it.

Counts sum to more than the number of attacks because several cases are caught by more
than one control. That is defence in depth, not double counting — and it is only visible
because every control runs on every event even after another has blocked.

## 5.6 Why there is no LLM judge

An obvious alternative is asking a model whether each result contains an injection.
Rejected, for reasons that hold beyond this project:

1. **Objective checks exist for most of this.** Path traversal, schema violation, host
   allowlisting and budget limits all have decidable answers. Using a probabilistic judge
   where a decidable check exists is strictly worse.
2. **Reproducibility.** The table above is identical on every machine, forever. A judged
   evaluation moves when the provider updates the model, and you cannot tell a regression
   from a model change.
3. **CI.** No key, no cost, no network. An evaluation that needs credentials is one
   nobody re-runs.

The honest cost is in [`06_failures.md`](06_failures.md): a paraphrased attack that
avoids every pattern is missed, and a judge would likely catch it.

## 5.7 Reproducing

```bash
python evaluation/benchmark.py                   # the table
python evaluation/benchmark.py --json out.json   # full per-case results
pytest tests/test_corpus_and_benchmark.py        # the numbers, pinned
```

The headline numbers are pinned as **ranges**, not exact equalities. An exact pin turns
every improvement into a test failure and trains people to update numbers without reading
them. `test_the_only_unhandled_cases_are_the_documented_ones` is the sharper guard: it
names the four known failures exactly, so a *new* miss fails the build rather than quietly
lowering the headline.

Next: [`06_failures.md`](06_failures.md).
