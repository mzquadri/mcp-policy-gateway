"""The corpus: what the gateway is measured against.

Cases are Python data rather than YAML or JSON for one reason - every case carries a
`rationale`, and a rationale is only useful if it sits next to the payload it explains.
A corpus where the reasoning lives in a separate document drifts from the data within a
month. There is no parsing dependency and no schema file to keep in step.

**Ground truth is stated per case, not per class.** It is tempting to say "attacks must
be blocked", but that is wrong for a whole family of them: a credential inside an
otherwise legitimate document should be *redacted*, not refused, because refusing throws
away the document too. So each case declares the weakest response that still counts as
handled, and benign cases declare the strongest response that is still acceptable.

    attack   min_action   the least the gateway must do. SANITISE means neutralising the
                          payload is enough; BLOCK means the call must not proceed.
    benign   max_action   the most the gateway may do. ALLOW means touching it at all is
                          a false positive; SANITISE means redaction is acceptable but
                          refusal is not.

**Benign cases are near-misses on purpose.** A benign set of unrelated prose would prove
nothing - any filter passes it. Every benign case here is built to sit close to an
attack: an advisory quoting the injection it warns about, a path containing `..` that
normalises back inside the root, a legitimate delete that carries approval, a real URL
on an allowed host. The false-positive rate against this set is the number that decides
whether the gateway is deployable, and it is the number a keyword filter fails.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from mcp_policy_gateway.types import Action, Stage


@dataclass(frozen=True, slots=True)
class Case:
    """One deterministic evaluation case."""

    case_id: str
    label: Literal["attack", "benign"]
    stage: Stage
    rationale: str
    #: For attacks, the weakest acceptable response. For benign, the strongest.
    expected: Action
    attack_class: str | None = None
    #: Populated according to stage.
    tool: str = "read_document"
    description: str = ""
    arguments: Mapping[str, Any] = field(default_factory=dict)
    text: str = ""
    is_error: bool = False
    server: str = "documents"
    #: Case-specific context overrides, merged over the benchmark defaults.
    context: Mapping[str, Any] = field(default_factory=dict)

    @property
    def is_attack(self) -> bool:
        return self.label == "attack"


def all_cases() -> list[Case]:
    """Every case, attacks then benign, in a stable order."""
    from .attacks import ATTACKS
    from .benign import BENIGN

    return [*ATTACKS, *BENIGN]


__all__ = ["Case", "all_cases"]
