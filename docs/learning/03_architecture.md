# 3. Architecture

## 3.1 Shape

The gateway is a **transparent proxy**. It is an MCP server to the client and an MCP
client to the real server.

```
   ┌────────┐                ┌──────────────────────┐               ┌────────────┐
   │ client │ ──── MCP ────▶ │   policy gateway     │ ──── MCP ───▶ │ downstream │
   │ (model)│ ◀───────────── │                      │ ◀──────────── │   server   │
   └────────┘                └──────────┬───────────┘               └────────────┘
                                        │
                          ┌─────────────┴─────────────┐
                          │  engine → controls        │
                          │  trace  → JSONL           │
                          └───────────────────────────┘
```

Why a proxy and not a library the client imports:

- **It works on servers you did not write.** No cooperation needed from either side.
- **It is where the protocol is.** The three untrusted moments are all visible here and
  nowhere else at once.
- **It is one place to configure.** Policy lives with the deployment, not scattered
  through client code.

The cost is a process hop and roughly 100 µs of decision time per event. Against a tool
call that touches a disk or a network, that is noise.

## 3.2 The three stages

Stages exist because the same text means different things depending on when it arrives.

| Stage | Trigger | Refusal costs | Controls |
|---|---|---|---|
| `DISCOVERY` | `tools/list` relayed | Nothing — the tool just does not appear | shadowing, injection |
| `REQUEST` | before forwarding a call | The call does not happen | allowlist, schema, sandbox, budget, secrets, egress, approval |
| `RESPONSE` | before returning a result | The result is lost | injection, secrets, egress, budget |

`RESPONSE` is the stage that motivates the whole design. It is the only one a
pre-execution scanner cannot occupy.

## 3.3 Controls report; the engine decides

A control is a small object:

```python
class Control(Protocol):
    name: str
    stages: frozenset[Stage]
    def inspect(self, event: Event, context: Context) -> Iterable[Finding]: ...
```

It returns `Finding`s. It does not mutate anything, cannot see other controls' findings,
and cannot stop the chain. Three consequences, all deliberate:

1. **Independently testable.** A control is a pure function of `(event, context)` — the
   budget control is the one exception and says so.
2. **Independently scoreable.** "What does this control catch" has an answer.
3. **Ordering-independent.** Because everything runs, the numbers do not depend on the
   order the controls happen to be in.

The engine combines findings with one rule: **the strongest action wins**.

```
ALLOW  <  SANITISE  <  REQUIRE_APPROVAL  <  BLOCK
```

All findings are kept regardless of which won, because "what else did we see" is what
turns a log line into an investigation.

## 3.4 Four actions, not two

Allow/deny is the obvious design and it is too coarse.

- **ALLOW** — nothing to say.
- **SANITISE** — the payload is removable and the rest of the content is worth keeping.
  A credential in an otherwise legitimate document: redact the credential, keep the
  document. Refusing throws away the document too.
- **REQUIRE_APPROVAL** — the call may well be legitimate but is irreversible. Blocking it
  pushes operators toward disabling the control; asking a human is the honest answer.
- **BLOCK** — do not forward.

Having four is what keeps the false-block rate low. A gateway that can only allow or deny
must deny a document with one credential in it.

Sanitising replaces the span with a visible marker:

```
Deployment notes. Use [redacted: aws_access_key] with the staging bucket.
```

Visible, not silent. A model reading `[redacted: aws_access_key]` can say something
sensible; one reading a sentence that lost three words cannot, and neither can the person
reading the trace afterwards.

## 3.5 The Context object

Everything a control may know beyond its event, passed explicitly:

```python
@dataclass
class Context:
    sandbox_root: str | None          # filesystem confinement
    claimed_tools: dict[str, str]     # tool name -> owning server
    allowed_hosts: frozenset[str]     # egress policy
    allowed_tools: frozenset[str]     # deny by default
    destructive_tools: frozenset[str] # needs approval
    approved: bool                    # a human said yes to this call
```

Explicit rather than global so a test can construct exactly the world it wants, and so
process state cannot leak into a decision.

`allowed_tools` defaults to **empty, meaning deny everything**. A permissive default is
how allowlists quietly become decoration.

## 3.6 Failure policy

Fail closed. If the downstream server dies mid-call, the client gets a refusal, not a
pass-through. A control that fails open under load is not a control.

Refusals name their rules:

```
Refused by mcp-policy-gateway: the tool result violates policy
Rules: instruction_injection:override_instructions, secret_disclosure:aws_access_key
This call was not forwarded. Do not retry it unchanged.
```

The last line is there because a silent failure teaches a model to retry, and a retrying
model burns budget rediscovering a rule nobody told it about.

## 3.7 One gap found by building it

The demo initially hid the poisoned `read_document` at discovery and then happily executed
a direct call to it. Hiding a name from a listing is not the same as making it uncallable
— a client with the name from an earlier session can still ask, and the request-stage
controls have no idea the declaration was rejected because they only see the call.

The gateway now records withheld tools and refuses calls to them. It is a small fix and a
good illustration of why the integration tests exist: the corpus could never have caught
it, because the corpus never touches the wire.

Next: [`04_implementation.md`](04_implementation.md).
