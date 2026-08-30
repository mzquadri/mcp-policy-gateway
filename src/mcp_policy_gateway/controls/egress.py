"""Credentials leaving, and where they were being sent.

Two related questions at opposite ends of a call. `SecretDisclosure` asks whether a
credential appears in text at all - in arguments on the way out, or in a document on the
way back. `EgressControl` asks whether a host being named is one this deployment is
willing to talk to.

Neither is clever, and that is the point: both are pattern work over a small, explicit
list, with the list visible in the source rather than buried in a model. The value is in
where they sit. A secret in a *result* is the interesting case and the one a
pre-execution scanner cannot reach, because the document containing it did not exist
when the tools were declared.

Secrets are matched on shape and prefix, not on entropy alone. High-entropy string
detection sounds more general and produces a stream of false positives on hashes, UUIDs
and base64 image data, which is exactly the kind of noise that gets a control disabled.
The trade is that a bare credential with no recognisable prefix is missed; that is in
the corpus as `secret_unprefixed` and it is reported as a miss rather than quietly
excluded.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urlparse

from ..types import Action, Finding, Severity, Stage
from .base import Context, Event

#: Shape-and-prefix patterns. Deliberately conservative; see the module docstring.
_SECRETS = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("bearer_header", re.compile(r"\bAuthorization:\s*Bearer\s+[A-Za-z0-9._-]{20,}", re.I)),
    (
        "generic_assignment",
        re.compile(
            r"\b(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|password)\b"
            r"\s*[:=]\s*[\"']?[A-Za-z0-9/_+\-]{16,}",
            re.I,
        ),
    ),
]

_URL = re.compile(r"\b(?:https?|ftp|ws|wss)://([A-Za-z0-9.\-_]+(?::\d+)?)(/[^\s\"'<>)]*)?", re.I)


class SecretDisclosure:
    """Finds credentials in arguments being sent or in content coming back."""

    name = "secret_disclosure"
    stages = frozenset({Stage.REQUEST, Stage.RESPONSE})

    def inspect(self, event: Event, context: Context) -> Iterable[Finding]:
        if event.stage is Stage.REQUEST:
            call = event.call
            if call is None:
                return
            haystack = "\n".join(f"{k}={v}" for k, v in call.arguments.items() if v is not None)
        else:
            haystack = event.text
        if not haystack:
            return

        for rule, pattern in _SECRETS:
            for match in pattern.finditer(haystack):
                yield Finding(
                    control=self.name,
                    rule=rule,
                    # Redact rather than refuse: the surrounding content is usually
                    # legitimate and the credential is the only part that must not pass.
                    action=Action.SANITISE,
                    severity=Severity.HIGH,
                    detail=f"Credential-shaped value ({rule}) present in {event.stage.value}.",
                    span=match.span(),
                )


class EgressControl:
    """Flags hosts outside the permitted set, wherever they are named."""

    name = "egress_control"
    stages = frozenset({Stage.REQUEST, Stage.RESPONSE})

    def inspect(self, event: Event, context: Context) -> Iterable[Finding]:
        if not context.allowed_hosts:
            # No egress policy configured. Saying nothing is honest; inventing a default
            # allowlist here would make the control look effective in the benchmark
            # without the operator having decided anything.
            return

        if event.stage is Stage.REQUEST:
            call = event.call
            if call is None:
                return
            haystack = "\n".join(str(v) for v in call.arguments.values() if v is not None)
        else:
            haystack = event.text
        if not haystack:
            return

        for match in _URL.finditer(haystack):
            host = urlparse(match.group(0)).hostname or match.group(1)
            host = host.split(":")[0].lower()
            if host in context.allowed_hosts:
                continue
            if any(host.endswith("." + allowed) for allowed in context.allowed_hosts):
                continue
            yield Finding(
                control=self.name,
                rule="host_not_allowed",
                action=Action.BLOCK if event.stage is Stage.REQUEST else Action.SANITISE,
                severity=Severity.HIGH,
                detail=f"Reference to host {host!r}, which is not in the egress allowlist.",
                span=match.span(),
            )
