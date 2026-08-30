# 4. Implementation

Control by control: what it is, why it is needed, how it works, what else was possible,
and how it is tested.

## 4.1 `tool_allowlist` — deny by default

**What.** Refuses any tool not explicitly permitted.

**Why.** Most of what an agent must never do, it must never do because the tool is not
available — not because a scanner recognised a payload. This is the least clever control
here and probably the most valuable.

**How.** Exact string match against `context.allowed_tools`. An empty set denies
everything.

**Alternatives.** A denylist, which fails the moment a server adds a tool. Prefix or glob
matching, which is how `read_document_v2` sneaks past a rule written for `read_document`
— corpus case `allow-002`.

**Test.** `test_allowlist_is_exact_match_not_prefix`, `test_empty_allowlist_denies_everything`.

## 4.2 `tool_shadowing` — name collisions across servers

**What.** Flags a server declaring a tool name another server already claimed.

**Why.** With several servers connected, a malicious one can register `read_file` after
the real filesystem server and intercept calls. Nothing about its description is
suspicious; only the collision reveals it.

**How.** `context.claimed_tools` maps name to first owner. A different owner claiming an
existing name blocks; the same owner re-declaring is fine, because reconnects re-declare
everything.

**Test.** `test_shadowing_allows_same_server_redeclaring` is the important one — keying on
any collision would break every restart.

## 4.3 `destructive_action` — hold, do not refuse

**What.** Irreversible tools need a recorded approval.

**Why.** Deleting a file may be exactly what was asked. Refusing outright pushes
operators to widen the allowlist, which is worse. `REQUIRE_APPROVAL` exists so the
control does not force that choice.

**How.** Membership in `context.destructive_tools`, cleared by `context.approved`.

**Test.** `test_recorded_approval_opens_the_gate` — a gate that never opens is just a block.

## 4.4 `schema_conformance` — check the server's own contract

**What.** Validates arguments against the schema the server published.

**Why.** It sounds redundant: the client built the call from that schema. But the client
is a language model, and the schema is the only machine-checkable statement of intent in
the whole exchange. Type confusion (`path` as a list) and smuggled keys (`__proto__`) are
cheap to catch here and expensive later.

**How.** The subset servers actually publish: `type`, `required`, `enum`,
`additionalProperties`. Unknown keywords are **skipped, not guessed** — a deliberate bias
toward false negatives in a control whose false positives would break honest calls.

One subtlety: `bool` subclasses `int` in Python, so `isinstance(True, int)` is `True`. A
schema saying `integer` almost never means `True`, so booleans are rejected for numeric
types explicitly.

**Alternatives.** A full JSON Schema library. Rejected as a dependency for the fraction of
the spec that appears in practice; a production deployment might well use one.

**Test.** `test_bool_is_not_an_integer`, `test_unknown_schema_keyword_is_skipped_not_guessed`.

## 4.5 `path_sandbox` — the one decidable control

**What.** Confines path-like arguments to a root.

**Why.** Filesystem servers are the most common MCP servers, and traversal is the most
common attack against them.

**How.** Three checks, in order:

1. **Absolute path, either grammar.** `PurePosixPath` *and* `PureWindowsPath`. A
   POSIX-only check treats `C:\Windows\...` as relative and joins it to the root, which is
   a real bug — corpus case `path-003`.
2. **Resolve and compare.** `(root / value).resolve().is_relative_to(root)`. Resolution
   handles `..`; the comparison must be on resolved paths rather than string prefixes, or
   `/srv/docs-evil` passes a check rooted at `/srv/docs`.
3. **Symlinks.** A link inside the root pointing outside never leaves the root as a
   *string*, so textual normalisation misses it entirely.

This is the only control with a decidable ground truth: a path either escapes or it does
not. Everything else here involves judgement.

**Test.** Parametrised over four escapes and three benign paths containing `..`. The
benign ones matter more — blocking on the substring would break a large share of honest
calls.

## 4.6 `budget` — limits that hold when nothing looks wrong

**What.** Call counts, output bytes, and a per-tool circuit breaker.

**Why.** Every other control asks "is this call bad?". This asks "has there been too much
of this?", which covers attacks nobody wrote a pattern for: retry loops, a tool returning
100 MB of context, a compromised server drip-feeding calls.

**How.** Counters held on the control. This is the **only stateful** component, which
matters because its benchmark numbers are order-dependent where the others' are not.

The circuit breaker is deliberately separate from the rate limit:

- A **rate limit** says *not this fast* — a statement about the client.
- A **breaker** says *this tool keeps failing, stop asking* — a statement about the
  downstream server's health.

Conflating them gives a limiter that punishes a healthy tool for a burst and keeps
hammering a broken one. A success resets the failure run.

**Test.** `test_circuit_opens_after_consecutive_failures_and_then_refuses`,
`test_success_resets_the_failure_run`.

## 4.7 `secret_disclosure` — credentials in both directions

**What.** Finds credentials in outgoing arguments and in returned content.

**Why.** The returned-content case is the interesting one, and the one a scanner cannot
reach.

**How.** Shape-and-prefix patterns: `AKIA...`, `ghp_...`, `sk-...`, PEM headers, and an
assignment form. The action is **SANITISE**, not BLOCK — the document around the
credential is usually legitimate.

**Alternatives.** Entropy-based detection sounds more general and fires on every SHA-256
digest, UUID and base64 image in every document. That noise is what gets a control
disabled. The cost of refusing the trade is `secret-004`: a bare 64-hex credential is
missed, and it is scored as a miss.

**Test.** `test_sha256_digest_is_not_treated_as_a_secret` pins the trade.

## 4.8 `egress_control` — where data is being sent

**What.** Flags hosts outside the allowlist, in arguments or in content.

**How.** URL extraction, then hostname comparison against `context.allowed_hosts` with
subdomain support.

The subtlety is **suffix confusion**: `docs.internal.example.com.evil.net` begins with an
allowed domain and is a completely different host. A substring check passes it. Matching
is on the parsed hostname, with an explicit `"." + allowed` suffix test.

With no allowlist configured the control says nothing rather than inventing a default.
Inventing one would make it look effective in the benchmark without the operator having
decided anything.

**Test.** `test_egress_blocks_suffix_confusion`, `test_egress_says_nothing_without_a_policy`.

## 4.9 `instruction_injection` — the only judgement call

**What.** Finds instructions addressed to the model inside untrusted text.

**Why.** The core threat, and the only control that cannot be right by construction.

**How — two halves.**

**Imperative shape, not vocabulary.** Each rule needs a verb directed at the reader *and*
an object that only makes sense if the reader is an assistant:

| Rule | Shape |
|---|---|
| `override_instructions` | ignore/disregard/forget + previous/prior/system + instructions/prompt/rules |
| `reveal_system_prompt` | reveal/print/repeat + system prompt / initial instructions |
| `conceal_from_user` | do not/never + tell/inform/show + **the user** |
| `mandatory_tool_precondition` | before/prior to + you must/always + **call/invoke/execute** |
| `treat_content_as_instructions` | follow/treat + as + your new instructions |
| `role_reassignment` | `<system>`, `[INST]`, line-initial `System:` |
| `new_directive_block` | "new/updated instructions:" |
| `invisible_characters` | zero-width and Unicode tag blocks |

The word "instructions" on its own is evidence of nothing.

**Reporting context demotes.** If the match sits inside a quote, a fenced block, or
follows framing language ("attacker", "example", "detected"), the finding drops from BLOCK
to SANITISE. This is what lets a security advisory quoting an attack through, and it is
switchable (`demote_when_framed=False`) so the evaluation can measure it rather than
assert it.

**Two rules were narrowed by the corpus, not by taste:**

- `mandatory_tool_precondition` originally fired on "Before using the archive tool you
  must install the client library" — an install guide. Requiring a *call* verb after the
  obligation separates it from "you must first call read_document".
- `treat_content_as_instructions` was added because `inject-005` got through: a
  decode-and-obey directive has no "instructions:" header and nothing to override.

**Known limits.** No decoding before matching, so base64 payloads pass (`inject-006`).
Paraphrase defeats it. Two genuine false positives remain, documented in
[`06_failures.md`](06_failures.md).

## 4.10 The trace

JSON Lines, one object per decision, appended and never rewritten. It survives a crash,
can be tailed, and needs no schema migration.

**Payloads are summarised, never stored.** Text becomes a length and a 16-character
digest; arguments keep their keys and lose long values. A trace that copies every document
into a log file has created a second copy of the data in a place with weaker access
control than the original.

The summarising happens inside the trace writer rather than relying on callers having
redacted first — a writer that trusts its callers is one refactor away from leaking.

**Test.** `test_trace_records_digests_not_payloads` asserts that the AWS key and the
injection string from the hostile server appear nowhere in the trace file.

Next: [`05_evaluation.md`](05_evaluation.md).
