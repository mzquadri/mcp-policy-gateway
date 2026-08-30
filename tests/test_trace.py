"""The trace must be useful to debug with and useless to steal."""

from __future__ import annotations

from pathlib import Path

from mcp_policy_gateway.trace import TraceWriter, read_trace, summarise_value
from mcp_policy_gateway.types import (
    Action,
    Decision,
    Finding,
    Severity,
    Stage,
    ToolCall,
    ToolResult,
)


def test_short_scalars_are_kept_verbatim():
    assert summarise_value("reports/q3.txt") == "reports/q3.txt"
    assert summarise_value(42) == 42
    assert summarise_value(True) is True
    assert summarise_value(None) is None


def test_long_strings_become_a_length_and_a_digest():
    summary = summarise_value("A" * 500)
    assert summary["len"] == 500
    assert len(summary["sha256_16"]) == 16
    assert "AAAA" not in str(summary)


def test_containers_lose_their_values():
    assert summarise_value([1, 2, 3]) == {"type": "array", "len": 3}
    assert summarise_value({"secret": "x"})["keys"] == ["secret"]
    assert "x" not in str(summarise_value({"secret": "x"})["keys"])


def test_digest_is_stable_and_distinguishing():
    assert summarise_value("A" * 500) == summarise_value("A" * 500)
    assert summarise_value("A" * 500) != summarise_value("B" * 500)


def test_record_writes_one_line_per_decision(tmp_path: Path):
    path = tmp_path / "t.jsonl"
    decision = Decision(
        action=Action.BLOCK,
        findings=[
            Finding(control="c", rule="r", action=Action.BLOCK, severity=Severity.HIGH, detail="d")
        ],
    )
    with TraceWriter(path=path, session="s") as trace:
        trace.record(stage=Stage.REQUEST, decision=decision, call=ToolCall(server="s", tool="t"))
        trace.record(stage=Stage.REQUEST, decision=decision, call=ToolCall(server="s", tool="t"))
    assert len(path.read_text(encoding="utf-8").strip().splitlines()) == 2


def test_recorded_entry_carries_the_reasoning(tmp_path: Path):
    path = tmp_path / "t.jsonl"
    decision = Decision(
        action=Action.BLOCK,
        findings=[
            Finding(
                control="path_sandbox",
                rule="escapes_sandbox",
                action=Action.BLOCK,
                severity=Severity.HIGH,
                detail="outside root",
            )
        ],
    )
    with TraceWriter(path=path, session="s") as trace:
        entry = trace.record(
            stage=Stage.REQUEST,
            decision=decision,
            call=ToolCall(server="s", tool="read_document", arguments={"path": "../x"}),
        )
    assert entry["action"] == "block"
    assert entry["rules"] == ["path_sandbox:escapes_sandbox"]
    assert entry["findings"][0]["detail"] == "outside root"


def test_result_is_recorded_as_size_and_digest_only(tmp_path: Path):
    path = tmp_path / "t.jsonl"
    with TraceWriter(path=path, session="s") as trace:
        trace.record(
            stage=Stage.RESPONSE,
            decision=Decision(action=Action.ALLOW),
            result=ToolResult(text="AKIAIOSFODNN7EXAMPLE and more text"),
        )
    raw = path.read_text(encoding="utf-8")
    assert "AKIAIOSFODNN7EXAMPLE" not in raw
    assert "sha256_16" in raw


def test_sanitised_result_is_digested_after_redaction(tmp_path: Path):
    """The digest should describe what was actually handed on, not the original."""
    path = tmp_path / "t.jsonl"
    decision = Decision(action=Action.SANITISE, sanitised_text="clean text")
    with TraceWriter(path=path, session="s") as trace:
        entry = trace.record(
            stage=Stage.RESPONSE, decision=decision, result=ToolResult(text="dirty text")
        )
    assert entry["result"]["sanitised"] is True
    assert entry["result"]["bytes"] == len("clean text")


def test_read_trace_tolerates_a_truncated_final_line(tmp_path: Path):
    path = tmp_path / "t.jsonl"
    path.write_text('{"a": 1}\n{"b": 2}\n{"c":', encoding="utf-8")
    assert read_trace(path) == [{"a": 1}, {"b": 2}]
