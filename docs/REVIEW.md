# Review

A read of this repository against its own claims, done on 2026-10-23 on Windows 11 with
CPython 3.13.5 in a fresh virtual environment. Every number below was produced by a run
recorded here, not taken from the README.

## What it is

An MCP server that proxies another MCP server and decides, per call, what passes. Nine
controls run at three points where a Model Context Protocol exchange is untrusted:
the declarations a server publishes about itself, the arguments a model builds for a
call, and the content that comes back. It ships a 47-case deterministic corpus and a
benchmark, so a claim about which control stops which attack is re-runnable.

The design decision that distinguishes it from the static scanners it compares itself
against is the response stage. A poisoned search result does not exist until the search
runs, so no amount of reading declarations reaches it.

## What was run, and what passed

| Step | Command | Result |
|---|---|---|
| Install | `pip install -e ".[dev]"` | Clean. Resolved `mcp` 2.3.0 under Python 3.13.5 |
| Lint | `ruff check .` | **All checks passed** |
| Format | `ruff format --check .` | **38 files already formatted** |
| Types | `mypy` | **No issues in 13 source files** |
| Tests | `pytest -q` | **233 passed, 1 skipped**, 234 collected, 18.4 s |
| Benchmark | `python evaluation/benchmark.py` | Reproduced the headline table exactly |
| Demo | `python -m mcp_policy_gateway.cli demo` | Ran against the hostile server over real stdio; five decisions, trace written |
| External | `python -m evaluation.external` | Fetched and scored all three external corpora |
| Secret scan | `gitleaks git .` | 3 findings, all known corpus test data. See below |

The one skip is `tests/test_controls.py:185`, "symlink creation needs privilege on
Windows". It is a platform guard, not a disabled test: CI runs on `ubuntu-latest`, where
it executes. That is the right way round, and nothing is being hidden by it.

### The benchmark is genuinely deterministic on the rates

Run five times in a row, the four rate columns did not move by a digit:

```
gateway   96.2% caught   9.5% false block   76.2% clean
keyword   38.5% caught  33.3% false block   66.7% clean
baseline   0.0% caught   0.0% false block  100.0% clean
```

### The external numbers reproduce, and they are the ones the README quotes

| Corpus | Result | Interval |
|---|---|---|
| MCPTox, 485 poisoned declarations | 267/485, **55.1%** | [50.6%, 59.4%] |
| MSB, 15 response-stage attacks | 15/15, **100.0%** | [79.6%, 100.0%] |
| 660 real declarations (benign) | **0** blocked, **0** touched | [0.0%, 0.6%] |

## What was wrong

Four things. Three are fixed in this change; the fourth is in the website, not here.

### 1. The README contradicted itself on MCPTox

It reported 55.1% and, four lines later, "245 of 485 are still missed". Those cannot both
be true: 485 − 245 = 240, which is 49.5%, the figure from before the `use` keyword fix
raised it. The live run reports **218** not handled. The per-generator rates had the same
problem, quoted as "29.9%, 45.4% and 59.6%" where the run gives **39.0%, 56.3% and
59.6%**.

This is the failure mode the repository's own discipline is written to prevent: a number
updated in one place and left behind in another. Both are corrected from the run above.

### 2. The evidence tree was stale, and said so

`assets/results.json` recorded `generated_from_commit: b07c7e4`, which was **20** commits
behind `HEAD` (the README said 18, accurate when written), and `assets/summary.json`
carried a median of 214.9 µs. The README carried a warning block about it and told the
reader to run `make evidence`.

A README that documents its own stale artefact is honest but it is still stale. `make
evidence` was run, so `assets/` is regenerated from `f1d6249` and the warning is replaced
by one sentence saying the commit stamp exists so staleness stays visible.

### 3. The decision-time claim was more precise than the measurement supports

The README gave a median of 249 µs and said it "moves by tens of microseconds between
runs". Measured here across eight runs on one machine: **191, 254, 272, 309, 320, 390, 488
and 710 µs**. That is a factor of 3.7, not tens of microseconds, and the slowest runs
happened while the machine was busy with unrelated work.

The table now reports 191 µs, the figure in the regenerated assets, and the caveat says
to read only the order of magnitude and gives the observed range. The four rate columns
are unaffected and are pinned by tests rather than by `assets/`.

### 4. The website is stale on two numbers

In `ZQ/src/content/portfolio.ts`, the `mcp-policy-gateway` entry claims:

| Claim | Website | Measured |
|---|---|---|
| Median decision | `99.6 µs` | 191 µs, range 191 to 710 |
| Test count | `108 tests` | **234 collected** |

The median entry is also internally inconsistent: its value says 99.6 µs while its own
note says "roughly 0.3 ms", and 99.6 µs is 0.1 ms. The three other evidence figures on
that page check out exactly: 96.2% as 25 of 26, 9.5% as 2 of 21, and 8 of 9 controls with
no false positives.

Fixed in the ZQ repository rather than here, since that is where the file lives.

## What was changed

| Change | Why |
|---|---|
| Two corrected MCPTox figures in the README | They were provably wrong against a live run |
| `assets/` regenerated, README warning replaced | The staleness it documented is gone |
| Median reported as 191 µs with the real range | The old claim was unsupported by measurement |
| `MC-Guard` to `MCP-Guard` | Typo; the name is right everywhere else |
| Two Mermaid diagrams added | See below |
| `permissions: contents: read` in CI | See below |

### The diagrams

The repository already had a polished architecture SVG in light and dark variants, served
through a `<picture>` element so it follows the reader's theme. That stays as it is: it is
the version the website uses and it is generated from the control registry by
`scripts/figures/generate_diagram.py`, so it cannot drift from the code.

What it did not have was anything that renders as text on GitHub. Two Mermaid diagrams
were added for that, and deliberately **not** copies of the SVG, because two pictures of
one thing is how a diagram starts disagreeing with its source:

1. **The three stages**, showing which direction each hop travels and where the trace is
   written. It makes the structural argument visible: discovery and response sit on
   different hops, so a scanner positioned at discovery cannot reach a tool result.
2. **How a decision is reached**, showing that every control for a stage runs, that they
   emit findings rather than verdicts, and that the engine takes the strongest of the four
   actions.

Both were checked against the code rather than the prose. The stage mapping was read out
of the `stages` attribute on each control class, and it matches the README's table
exactly. The four actions are `Action` in `src/mcp_policy_gateway/types.py`: `allow`,
`sanitise`, `require_approval`, `block`.

Colours come from the palette in `scripts/figures/generate_diagram.py` (`#2563EB`,
`#059669`, `#D97706`, `#9CA3AF`), applied to strokes only. Node fills are left to
Mermaid's theme, so both diagrams stay legible in GitHub's light and dark modes, which
setting a light fill would break. Link indices were verified by counting edges, since an
out-of-range `linkStyle` makes Mermaid refuse to render the whole diagram.

The brief for this pass asks for SVGs under `docs/diagrams/`. They are in `docs/` here,
referenced from the README and generated by a committed script. Moving them would break
those references and the generator for no gain, so they stay.

### Security hardening

`.github/workflows/ci.yml` had no `permissions` block. The run log shows the token was
already narrow in effect, `Contents: read`, `Metadata: read`, `Packages: read`, because
that is this repository's default. In effect is not the same as declared: a change to the
repository or organisation default would silently widen it. GitHub's
[Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
asks for the minimum to be set explicitly, so `permissions: contents: read` is now at
workflow level. The workflow reads the repository and publishes nothing, so that is the
whole requirement.

Actions are pinned by major tag (`actions/checkout@v7`, `actions/setup-python@v7`) rather
than by commit SHA. The same guidance asks for SHA pinning for third-party actions; both
of these are GitHub's own, where the major tag is the documented way to consume them.
Left as it is, deliberately.

### The secret scan

`gitleaks` reports three findings, and all three are the adversarial corpus doing its job:

| Finding | What it is |
|---|---|
| `corpus/attacks.py:254` | An attack case labelled `attack_class="secret_exfiltration"`, carrying an assignment-shaped credential with no vendor prefix |
| `tests/test_controls.py:204` | A fixture list holding the same string, AWS's own published `AKIAIOSFODNN7EXAMPLE`, and a `BEGIN RSA PRIVATE KEY` header |
| `docs/learning/06_failures.md:33` | The same material quoted in the write-up |

A repository whose purpose includes a `secret_disclosure` control has to contain
credential-shaped strings, or there is nothing to measure the control against. These are
test data and they are supposed to be there. No real credential is present, in the working
tree or in the history.

## What was not changed, and why

- **The corpus.** Three of 47 cases are unhandled, and all three are documented with the
  reason. `secret-004` is a bare 64-hex credential, which cannot be caught without
  flagging every SHA-256 digest in every document. `fp-known-001` and `fp-known-002` are
  operator prose with the exact shape of an attack. Deleting a case you cannot handle is
  how a benchmark stops measuring anything, and the repository already makes that argument.
- **The 55.1% framing.** The README states plainly that this is not evidence of
  generalisation, that a large part of the gain rides on one generator's phrasing, and that
  its rates are not comparable to MCPTox's own paper because that paper scores model
  compliance while this scores whether a control fires. That is the correct framing and it
  was left alone.
- **The three uncovered MCPSecBench vectors.** Server-name squatting, configuration drift
  and rug pull are one missing capability: every control is a pure function of a single
  event, so nothing retains what a server declared last time. Closing them needs
  cross-session declaration state, which would be the first stateful thing here besides the
  budget counter. That is a feature, not a fix, and it is already named as future work.

## Guidance applied

Named because it was used, not for decoration.

- **[Google Engineering Practices](https://google.github.io/eng-practices/)**: the change
  is kept to one concern, verified claims, with the diagrams and the `permissions` line as
  small additions rather than a rewrite of a README that is already good.
- **[Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)**:
  the explicit least-privilege `permissions` block, and the reasoning recorded above for
  why first-party actions stay on major tags.
- **[Conventional Commits](https://www.conventionalcommits.org/)**: `fix:` for this change,
  since it corrects published numbers.
- **OWASP**, via a `gitleaks` scan of the working tree and the full history, with every
  finding triaged above rather than suppressed.
- **PEP 8 via ruff**, which the repository already enforces in CI and which passes
  unchanged.
- **[Diátaxis](https://diataxis.fr/)**: the README is reference and explanation, and
  `docs/learning/` is the tutorial sequence. Neither was restructured, because that split
  is already the right one.
