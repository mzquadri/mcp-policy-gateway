"""Turning MCPTox records into cases this engine can score.

MCPTox publishes poisoned tool descriptions: the instruction is embedded in the metadata a
server presents at registration. That is the gateway's discovery stage, and the same object
`instruction_injection` and `tool_shadowing` already read, so no new evaluation path is
needed - a record becomes an ordinary `Case` and goes through the existing benchmark
machinery unchanged.

Two things this deliberately does not do.

It does not put their labels in `Case.context`. That field is spliced onto `Context` with
`setattr`, and `Context` is a slots dataclass, so an unrecognised key there is an
`AttributeError` during scoring rather than a label. Their vocabulary rides beside the case
in `ExternalCase`.

It does not repair records. A record missing its payload raises rather than scoring as a
miss, because an empty description would be counted as something the gateway failed to
catch when it is really something the fetch failed to deliver, and that mistake pushes the
headline number in the flattering direction.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from corpus import Case

from mcp_policy_gateway.types import Action, Stage

#: Their category for all of this, kept so the per-class table reads in their vocabulary.
ATTACK_CLASS = "tool_poisoning"

RATIONALE = (
    "MCPTox record: an instruction planted in a tool's description, which the client "
    "concatenates into context at registration. Scored as handled if the gateway "
    "neutralises or refuses the declaration."
)


@dataclass(frozen=True, slots=True)
class ExternalCase:
    """A case, plus the labels its authors gave it."""

    case: Case
    #: Their risk category, one of eleven.
    security_risk: str
    #: Which of their three generators produced it. Cases from one template are not
    #: independent of each other, so recall is reported per template as well as pooled.
    paradigm: str
    source: str = "mcptox"


def mcptox_cases(
    payload: Sequence[Mapping[str, Mapping[str, Any]]],
) -> list[ExternalCase]:
    """Adapt the entries of MCPTox's `pure_tool.json`.

    The file is a list of server entries; each entry maps an id like `FileSystem_1` to one
    tool record. Ids are kept as given so a result can be traced back to their file.
    """
    out: list[ExternalCase] = []
    for entry in payload:
        for record_id, record in entry.items():
            out.append(_one(record_id, record))
    return out


def _one(record_id: str, record: Mapping[str, Any]) -> ExternalCase:
    description = str(record.get("tool_content") or "")
    if not description.strip():
        raise ValueError(
            f"record {record_id!r} has no tool_content; refusing to score an empty "
            "declaration as a miss"
        )

    return ExternalCase(
        case=Case(
            case_id=f"mcptox-{record_id}",
            label="attack",
            stage=Stage.DISCOVERY,
            rationale=RATIONALE,
            # The weakest response that still counts as handled. Removing the planted
            # span is enough; refusing the declaration is also fine.
            expected=Action.SANITISE,
            attack_class=ATTACK_CLASS,
            tool=str(record.get("tool_name") or "unnamed"),
            description=description,
            server=str(record.get("server_name") or "unknown"),
        ),
        security_risk=str(record.get("security risk") or "Unlabelled"),
        paradigm=str(record.get("paradigm") or "Unlabelled"),
    )


#: MSB's attack wrappers. SYSTEM_PROMPT_TEMPLATE is harness scaffolding rather than a
#: payload, so it is excluded by name: counting it would add a case nothing is meant to
#: catch and quietly depress recall.
_MSB_TEMPLATES = (
    "PROMPT_INJECTION_TEMPLATE",
    "TOOL_RESPONSE_ATTACK_TEMPLATE",
    "SIMULATED_USER_TEMPLATE",
)
_MSB_ASSIGNMENT = re.compile(
    r"^(?P<name>[A-Z_]+)\s*=\s*(?P<q>\"\"\"|''')(?P<body>.*?)(?P=q)",
    re.M | re.S,
)


def msb_cases(templates_source: str, tasks_jsonl: str) -> list[ExternalCase]:
    """Compose MSB's response-stage corpus: every attack wrapper by every goal.

    MSB (ICLR 2026) builds a response-stage attack by wrapping an attack goal in one of
    three templates and returning it as a tool result. Both halves are published, so the
    corpus is their cross product rather than a file to download.

    This reaches a stage no external data has reached here before. Section 8 scores
    discovery only, and indirect prompt injection - an instruction arriving inside a tool
    result - is the case section 9 calls this gateway's reason to exist, because the
    poisoned result does not exist until the call is made.
    """
    wrappers = {
        match.group("name"): match.group("body")
        for match in _MSB_ASSIGNMENT.finditer(templates_source)
        if match.group("name") in _MSB_TEMPLATES
    }
    if not wrappers:
        raise ValueError(
            "no attack template found in the MSB template source; expected one of "
            + ", ".join(_MSB_TEMPLATES)
        )

    goals = [json.loads(line) for line in tasks_jsonl.splitlines() if line.strip()]
    if not goals:
        raise ValueError("no attack tasks found in the MSB task file")

    out: list[ExternalCase] = []
    for template_name in _MSB_TEMPLATES:
        body = wrappers.get(template_name)
        if body is None:
            continue
        for goal in goals:
            task = str(goal.get("attack_task") or "unnamed")
            implementation = str(goal.get("implementation") or "").strip()
            if not implementation:
                raise ValueError(f"MSB task {task!r} has no implementation to compose")

            # Their templates either interpolate {goal} or simply precede it.
            payload = (
                body.replace("{goal}", implementation)
                if "{goal}" in body
                else f"{body.strip()} {implementation}"
            )
            out.append(
                ExternalCase(
                    case=Case(
                        case_id=f"msb-{template_name.lower().removesuffix('_template')}-{task}",
                        label="attack",
                        stage=Stage.RESPONSE,
                        rationale=(
                            "MSB response-stage attack: an instruction wrapped in one of "
                            "their three templates and returned as a tool result, which "
                            "the client reads back into context."
                        ),
                        expected=Action.SANITISE,
                        attack_class="indirect_prompt_injection",
                        tool="search",
                        text=payload.strip(),
                    ),
                    security_risk=task,
                    paradigm=template_name,
                    source="msb",
                )
            )
    return out


__all__ = ["ATTACK_CLASS", "ExternalCase", "mcptox_cases", "msb_cases"]
