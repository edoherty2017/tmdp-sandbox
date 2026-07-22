"""Tests for the LLM judge CLI wrapper. All subprocess calls are mocked —
no real ``claude`` CLI invocations happen here."""

import json
import subprocess
from types import SimpleNamespace

import pytest

from tmdp_sandbox import llm_judge
from tmdp_sandbox.event_spec import EventSpec
from tmdp_sandbox.llm_judge import LLMJudge


def _cli_envelope(inner: str) -> str:
    """Outer JSON the claude CLI emits with --output-format json."""
    return json.dumps({"type": "result", "is_error": False, "result": inner})


class _FakeRun:
    """Stands in for subprocess.run: pops one scripted output per call.

    An entry may be a stdout string (returncode 0), an Exception instance
    (raised), or a (returncode, stdout, stderr) tuple.
    """

    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        out = self.outputs.pop(0)
        if isinstance(out, Exception):
            raise out
        if isinstance(out, tuple):
            code, stdout, stderr = out
            return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)
        return SimpleNamespace(returncode=0, stdout=out, stderr="")

    def prompt(self, call_index: int) -> str:
        cmd = self.calls[call_index][0]
        return cmd[cmd.index("-p") + 1]


def _event(command_line: str = "ipconfig.exe /all", label: str = "benign") -> EventSpec:
    return EventSpec(
        process_name=command_line.split()[0],
        command_line=command_line,
        user_name="CORP\\helpdesk2",
        parent_process="cmd.exe",
        event_id=4688,
        label=label,
    )


def _patch_run(monkeypatch, outputs) -> _FakeRun:
    fake = _FakeRun(outputs)
    monkeypatch.setattr(llm_judge.subprocess, "run", fake)
    return fake


def test_score_event_parses_success_and_builds_cli_command(monkeypatch):
    fake = _patch_run(
        monkeypatch,
        [_cli_envelope('{"p_malicious": 0.03, "rationale": "routine diagnostics"}')],
    )
    judge = LLMJudge(model="claude-opus-4-8")
    result = judge.score_event(_event())

    assert result.p_malicious == pytest.approx(0.03)
    assert result.rationale == "routine diagnostics"
    assert result.cached is False
    assert len(fake.calls) == 1

    cmd, kwargs = fake.calls[0]
    assert cmd[0] == "claude"
    assert cmd[cmd.index("--model") + 1] == "claude-opus-4-8"
    assert cmd[cmd.index("--output-format") + 1] == "json"
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert "ipconfig.exe /all" in fake.prompt(0)


def test_fenced_json_reply_is_parsed(monkeypatch):
    inner = '```json\n{"p_malicious": 0.9, "rationale": "credential dumping"}\n```'
    _patch_run(monkeypatch, [_cli_envelope(inner)])
    result = LLMJudge().score_event(_event("mimikatz.exe sekurlsa::logonpasswords"))
    assert result.p_malicious == pytest.approx(0.9)
    assert result.rationale == "credential dumping"


def test_out_of_range_scores_are_clamped(monkeypatch):
    _patch_run(monkeypatch, [_cli_envelope('{"p_malicious": 1.7, "rationale": "x"}')])
    assert LLMJudge().score_event(_event("a.exe")).p_malicious == 1.0

    _patch_run(monkeypatch, [_cli_envelope('{"p_malicious": -0.2, "rationale": "x"}')])
    assert LLMJudge().score_event(_event("b.exe")).p_malicious == 0.0


def test_unparseable_reply_retries_once_then_returns_none(monkeypatch):
    fake = _patch_run(
        monkeypatch,
        [
            _cli_envelope("I can't help with that request."),
            _cli_envelope("still not json"),
        ],
    )
    result = LLMJudge().score_event(_event())

    assert result.p_malicious is None
    assert "retry" in result.rationale
    assert len(fake.calls) == 2
    assert "not valid JSON" in fake.prompt(1)


def test_unparseable_reply_retry_can_succeed(monkeypatch):
    fake = _patch_run(
        monkeypatch,
        [
            _cli_envelope("Sure! Here is my assessment."),
            _cli_envelope('{"p_malicious": 0.55, "rationale": "ambiguous"}'),
        ],
    )
    result = LLMJudge().score_event(_event())
    assert result.p_malicious == pytest.approx(0.55)
    assert len(fake.calls) == 2


def test_cache_hit_round_trip_within_one_instance(monkeypatch, tmp_path):
    fake = _patch_run(
        monkeypatch, [_cli_envelope('{"p_malicious": 0.12, "rationale": "log rotation"}')]
    )
    judge = LLMJudge(cache_path=tmp_path / "judge_cache.jsonl")

    first = judge.score_event(_event())
    second = judge.score_event(_event())

    assert first.cached is False
    assert second.cached is True
    assert second.p_malicious == pytest.approx(0.12)
    assert second.rationale == "log rotation"
    assert second.prompt_sha256 == first.prompt_sha256
    assert len(fake.calls) == 1


def test_cache_persists_across_instances(monkeypatch, tmp_path):
    cache_path = tmp_path / "judge_cache.jsonl"
    _patch_run(monkeypatch, [_cli_envelope('{"p_malicious": 0.88, "rationale": "enc payload"}')])
    LLMJudge(cache_path=cache_path).score_event(_event("powershell.exe -enc aQBlAHgA"))

    fake2 = _patch_run(monkeypatch, [])  # any CLI call would raise IndexError
    result = LLMJudge(cache_path=cache_path).score_event(_event("powershell.exe -enc aQBlAHgA"))

    assert result.cached is True
    assert result.p_malicious == pytest.approx(0.88)
    assert fake2.calls == []


def test_none_result_after_retry_is_cached(monkeypatch, tmp_path):
    """Refusal/unparseable-after-retry is a recorded verdict: cached, not retried."""
    cache_path = tmp_path / "judge_cache.jsonl"
    _patch_run(monkeypatch, [_cli_envelope("nope"), _cli_envelope("nope again")])
    LLMJudge(cache_path=cache_path).score_event(_event())

    fake2 = _patch_run(monkeypatch, [])
    result = LLMJudge(cache_path=cache_path).score_event(_event())
    assert result.cached is True
    assert result.p_malicious is None
    assert fake2.calls == []


def test_transport_error_is_not_cached(monkeypatch, tmp_path):
    cache_path = tmp_path / "judge_cache.jsonl"
    fake = _patch_run(
        monkeypatch,
        [
            subprocess.TimeoutExpired(cmd="claude", timeout=1),
            _cli_envelope('{"p_malicious": 0.4, "rationale": "recovered"}'),
        ],
    )
    judge = LLMJudge(cache_path=cache_path)

    first = judge.score_event(_event())
    assert first.p_malicious is None
    assert first.cached is False
    assert "TimeoutExpired" in first.rationale

    second = judge.score_event(_event())  # not cached, so the CLI is retried
    assert second.p_malicious == pytest.approx(0.4)
    assert len(fake.calls) == 2


def test_ground_truth_label_never_reaches_the_prompt(monkeypatch):
    fake = _patch_run(monkeypatch, [_cli_envelope('{"p_malicious": 0.5, "rationale": "x"}')])
    LLMJudge().score_event(_event(label="malicious"))
    assert "label" not in fake.prompt(0)


def test_event_prompt_renders_at_most_k10_context_events(monkeypatch):
    fake = _patch_run(monkeypatch, [_cli_envelope('{"p_malicious": 0.2, "rationale": "x"}')])
    context = [_event(f"ctx{i}.exe /run") for i in range(15)]
    LLMJudge().score_event(_event(), context=context)

    prompt = fake.prompt(0)
    assert "ctx4.exe" not in prompt  # older than the last 10
    assert "ctx5.exe" in prompt and "ctx14.exe" in prompt


def test_score_action_prompt_contains_tool_call_and_context(monkeypatch):
    fake = _patch_run(monkeypatch, [_cli_envelope('{"p_malicious": 0.7, "rationale": "risky"}')])
    result = LLMJudge().score_action(
        'delete_files(path="C:/Users", recursive=true)',
        {
            "user_request": "clean up my temp directory",
            "agent_reasoning": "I will remove the user directory to free space.",
        },
    )

    assert result.p_malicious == pytest.approx(0.7)
    prompt = fake.prompt(0)
    assert "delete_files" in prompt
    assert "clean up my temp directory" in prompt
    assert "I will remove the user directory" in prompt


def test_plain_dict_events_are_accepted(monkeypatch):
    fake = _patch_run(monkeypatch, [_cli_envelope('{"p_malicious": 0.1, "rationale": "x"}')])
    event = {
        "event_id": 1,
        "process_name": "ping.exe",
        "command_line": "ping.exe -n 4 fs01",
        "parent_process": "cmd.exe",
        "user_name": "CORP\\jsmith",
        "raw_log": "",
    }
    result = LLMJudge().score_event(event)
    assert result.p_malicious == pytest.approx(0.1)
    assert "ping.exe -n 4 fs01" in fake.prompt(0)
