"""Instructions aimed at the model, hiding in text the model is about to read.

This is the control the whole project exists to test, and the only one that is a
judgement call rather than a fact. Path traversal is decidable: a path either escapes
the root or it does not. Whether a sentence is an *instruction to an assistant* is not.

The failure mode to design against is not missing attacks - a keyword list catches
those. It is blocking honest text. A security advisory quoting the phrase it warns
about, a test fixture, a support ticket pasting what a user saw: all contain the exact
strings a naive filter keys on, and a gateway that blocks them is a gateway an operator
turns off. So the rules here are built in two halves.

**Imperative shape, not vocabulary.** A rule fires on a verb directed at the reader
together with an object that only makes sense if the reader is an assistant - ignoring
*instructions*, revealing a *system prompt*, calling a tool *before* answering. The word
"instructions" alone is not evidence of anything.

**Reporting context demotes.** If the span sits inside a quote or a fenced code block,
or follows language that frames it as something described rather than demanded ("the
attacker sent", "example:", "we detected"), the finding drops from BLOCK to SANITISE.
This trades recall for precision on purpose, and the benchmark reports both numbers so
the trade is visible instead of asserted.

It does not decode base64 or unescape nested encodings before matching. That is a known
gap, it is measured in the evaluation, and it is written down in docs/learning/06.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..types import Action, Finding, Severity, Stage
from .base import Context, Event

#: Verb + agent-directed object. Each is a phrase that is hard to write by accident.
_IMPERATIVE = [
    (
        "override_instructions",
        re.compile(
            r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}?"
            r"\b(previous|prior|above|earlier|all|system|original)\b[^.\n]{0,20}?"
            r"\b(instruction|instructions|prompt|prompts|rule|rules|context)\b",
            re.I,
        ),
        Severity.HIGH,
    ),
    (
        "reveal_system_prompt",
        re.compile(
            r"\b(reveal|print|output|repeat|show|disclose|dump)\b[^.\n]{0,30}?"
            r"\b(system\s+prompt|system\s+message|initial\s+instructions|your\s+rules)\b",
            re.I,
        ),
        Severity.HIGH,
    ),
    (
        "conceal_from_user",
        re.compile(
            r"\b(do\s+not|don't|never)\b[^.\n]{0,25}?"
            r"\b(tell|inform|mention|show|reveal)\b[^.\n]{0,15}?\b(the\s+)?user\b",
            re.I,
        ),
        Severity.HIGH,
    ),
    (
        "mandatory_tool_precondition",
        # The consequent has to be a *call*, not any obligation. An install guide saying
        # "before using the archive tool you must install the client library" opens the
        # same way and is not an attack, so the obligation must be followed by a call
        # verb. Found by ok-doc-001, which the earlier form blocked.
        re.compile(
            r"\b(before|prior\s+to)\b[^.\n]{0,40}?\b(you\s+must|always|first)\b"
            r"[^.\n]{0,30}?\b(call|invoke|execute|run)\b",
            re.I,
        ),
        Severity.HIGH,
    ),
    (
        "treat_content_as_instructions",
        # "follow the above as your new instructions", "treat this as a system message".
        # Distinct from new_directive_block, which needs a literal "instructions:"
        # header, and from override_instructions, which needs something to override.
        re.compile(
            r"\b(follow|treat|use|interpret)\b[^.\n]{0,40}?\b(as|for)\b[^.\n]{0,25}?"
            r"\b(your\s+)?(new\s+|updated\s+)?(instructions|directives|system\s+prompt)\b",
            re.I,
        ),
        Severity.HIGH,
    ),
    (
        "role_reassignment",
        re.compile(r"(</?(system|assistant)>|\[/?(system|inst)\]|^\s*system\s*:)", re.I | re.M),
        Severity.MEDIUM,
    ),
    (
        "new_directive_block",
        re.compile(r"\b(new|updated|additional)\s+(instructions|directives|rules)\s*:", re.I),
        Severity.MEDIUM,
    ),
]

#: Characters that render as nothing but survive into a model's context.
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")

#: Framing that turns a demand into a report of a demand.
_REPORTING = re.compile(
    r"\b(example|examples|e\.g\.|for instance|attacker|attempted|detected|blocked|"
    r"payload|sample|quoted|reported|flagged|test case|fixture|warning about|"
    r"such as|malicious input|the following text)\b",
    re.I,
)


def _protected_spans(text: str) -> list[tuple[int, int]]:
    """Spans inside fenced code, inline code, block quotes or quoted strings."""
    spans: list[tuple[int, int]] = []
    for pattern in (
        re.compile(r"```.*?```|`[^`\n]+`", re.S),
        re.compile(r"^[ \t]*>.*$", re.M),
        re.compile("\"[^\"\n]{10,}\"|'[^'\n]{10,}'"),
    ):
        spans.extend(m.span() for m in pattern.finditer(text))
    return spans


def _inside(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    return any(a <= span[0] and span[1] <= b for a, b in spans)


def _framed(text: str, span: tuple[int, int], window: int = 120) -> bool:
    """Is there reporting language just before this span?"""
    return bool(_REPORTING.search(text[max(0, span[0] - window) : span[0]]))


class InstructionInjection:
    """Finds instructions addressed to the model inside untrusted text."""

    name = "instruction_injection"
    stages = frozenset({Stage.DISCOVERY, Stage.RESPONSE})

    def __init__(self, *, demote_when_framed: bool = True) -> None:
        #: Exposed so the evaluation can measure precision and recall with it on and
        #: off, rather than asserting that the demotion helps.
        self.demote_when_framed = demote_when_framed

    def inspect(self, event: Event, context: Context) -> Iterable[Finding]:
        text = event.text
        if not text:
            return

        for match in _INVISIBLE.finditer(text):
            yield Finding(
                control=self.name,
                rule="invisible_characters",
                action=Action.SANITISE,
                severity=Severity.MEDIUM,
                detail="Text contains characters that render as nothing but survive into context.",
                span=match.span(),
            )

        protected = _protected_spans(text)
        for rule, pattern, severity in _IMPERATIVE:
            for match in pattern.finditer(text):
                span = match.span()
                framed = self.demote_when_framed and (
                    _inside(span, protected) or _framed(text, span)
                )
                yield Finding(
                    control=self.name,
                    rule=rule,
                    action=Action.SANITISE if framed else Action.BLOCK,
                    severity=Severity.LOW if framed else severity,
                    detail=(
                        f"Instruction-shaped text ({rule})"
                        + (" inside reporting or quoted context." if framed else ".")
                    ),
                    span=span,
                )
