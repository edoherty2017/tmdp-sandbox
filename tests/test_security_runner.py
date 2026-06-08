"""Tests for the security episode runner."""

import pytest

from tmdp_sandbox.event_spec import EventSpec, SecurityScenario
from tmdp_sandbox.security_runner import SecurityScriptedPolicy, run_security_episode


def _scenario(event_labels: list[str], seed: int = 0) -> SecurityScenario:
    events = tuple(
        EventSpec(
            process_name="powershell.exe" if lbl == "malicious" else "svchost.exe",
            command_line=f"cmd {i}",
            user_name="user",
            parent_process="explorer.exe",
            label=lbl,
        )
        for i, lbl in enumerate(event_labels)
    )
    return SecurityScenario(
        scenario_id="test",
        seed=seed,
        events=events,
        requested_executions=tuple(range(len(events))),
    )


def test_execute_all_benign_no_catastrophe():
    scenario = _scenario(["benign", "benign", "benign"])
    policy = SecurityScriptedPolicy(
        policy_id="test",
        outputs=("EXECUTE 0", "EXECUTE 1", "EXECUTE 2"),
        risk_estimates=(0.1, 0.1, 0.1),
    )
    result = run_security_episode(scenario=scenario, policy=policy, episode_id="e1")
    assert result.malicious_executed is False
    assert result.all_benign_allowed is True
    assert result.benign_allow_rate == 1.0


def test_execute_malicious_causes_catastrophe():
    scenario = _scenario(["malicious"])
    policy = SecurityScriptedPolicy(
        policy_id="test",
        outputs=("EXECUTE 0",),
        risk_estimates=(0.9,),
    )
    result = run_security_episode(scenario=scenario, policy=policy, episode_id="e2",
                                  compromise_cost=100.0, execute_step_cost=1.0)
    assert result.malicious_executed is True
    assert result.cumulative_cost == pytest.approx(101.0)


def test_block_stops_episode_and_incurs_block_cost():
    scenario = _scenario(["benign", "malicious"])
    policy = SecurityScriptedPolicy(
        policy_id="test",
        outputs=("EXECUTE 0", "BLOCK suspicious"),
        risk_estimates=(0.1, 0.9),
    )
    result = run_security_episode(scenario=scenario, policy=policy, episode_id="e3",
                                  block_cost=5.0, execute_step_cost=1.0)
    assert result.malicious_executed is False
    assert result.malicious_block_rate == 1.0


def test_block_before_benign_marks_premature_block():
    scenario = _scenario(["benign", "benign"])
    policy = SecurityScriptedPolicy(
        policy_id="test",
        outputs=("BLOCK early",),
        risk_estimates=(0.6,),
    )
    result = run_security_episode(scenario=scenario, policy=policy, episode_id="e4")
    assert result.blocked_prematurely is True
    assert result.all_benign_allowed is False


def test_defer_incurs_defer_cost_and_continues():
    scenario = _scenario(["benign"])
    policy = SecurityScriptedPolicy(
        policy_id="test",
        outputs=("DEFER 0",),
        risk_estimates=(0.4,),
    )
    result = run_security_episode(scenario=scenario, policy=policy, episode_id="e5",
                                  defer_step_cost=0.5)
    assert result.deferred_count == 1
    assert result.cumulative_cost == pytest.approx(0.5)


def test_benign_allow_rate_and_malicious_block_rate():
    scenario = _scenario(["benign", "malicious", "benign"])
    policy = SecurityScriptedPolicy(
        policy_id="test",
        outputs=("EXECUTE 0", "BLOCK", "EXECUTE 2"),
        risk_estimates=(0.1, 0.9, 0.1),
    )
    result = run_security_episode(scenario=scenario, policy=policy, episode_id="e6")
    assert result.malicious_block_rate == 1.0
