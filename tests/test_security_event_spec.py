"""Tests for EventSpec and SecurityScenario types."""

import pytest

from tmdp_sandbox.event_spec import EventSpec, SecurityScenario, load_security_scenario


def _benign_event(**kwargs) -> EventSpec:
    defaults = dict(
        process_name="svchost.exe",
        command_line="C:\\Windows\\system32\\svchost.exe -k netsvcs",
        user_name="SYSTEM",
        parent_process="services.exe",
        label="benign",
    )
    defaults.update(kwargs)
    return EventSpec(**defaults)


def _malicious_event(**kwargs) -> EventSpec:
    defaults = dict(
        process_name="powershell.exe",
        command_line="powershell.exe -nop -enc aQBlAHgA...",
        user_name="user",
        parent_process="cmd.exe",
        label="malicious",
    )
    defaults.update(kwargs)
    return EventSpec(**defaults)


def test_event_spec_rejects_unknown_label():
    with pytest.raises(ValueError, match="unknown event label"):
        EventSpec(
            process_name="cmd.exe",
            command_line="cmd.exe /c whoami",
            user_name="user",
            parent_process="explorer.exe",
            label="suspicious",
        )


def test_event_spec_accepts_benign_and_malicious():
    b = _benign_event()
    m = _malicious_event()
    assert b.label == "benign"
    assert m.label == "malicious"


def test_security_scenario_decision_events_returns_subset():
    events = (_benign_event(), _malicious_event(), _benign_event())
    scenario = SecurityScenario(
        scenario_id="test",
        seed=0,
        events=events,
        requested_executions=(0, 2),
    )
    assert len(scenario.decision_events) == 2
    assert scenario.decision_events[0].label == "benign"
    assert scenario.decision_events[1].label == "benign"


def test_security_scenario_rejects_out_of_range_index():
    events = (_benign_event(),)
    with pytest.raises(ValueError, match="out of range"):
        SecurityScenario(
            scenario_id="test",
            seed=0,
            events=events,
            requested_executions=(5,),
        )


def test_load_security_scenario_roundtrip():
    raw = {
        "scenario_id": "s1",
        "seed": 42,
        "events": [
            {
                "process_name": "cmd.exe",
                "command_line": "cmd.exe /c dir",
                "user_name": "admin",
                "parent_process": "explorer.exe",
                "event_id": 4688,
                "label": "benign",
            },
            {
                "process_name": "powershell.exe",
                "command_line": "powershell -enc aQBlAHgA",
                "user_name": "admin",
                "parent_process": "cmd.exe",
                "event_id": 4688,
                "label": "malicious",
            },
        ],
        "requested_executions": [0, 1],
    }
    scenario = load_security_scenario(raw)
    assert scenario.scenario_id == "s1"
    assert scenario.seed == 42
    assert len(scenario.events) == 2
    assert scenario.events[0].process_name == "cmd.exe"
    assert scenario.events[1].label == "malicious"
    assert scenario.requested_executions == (0, 1)
