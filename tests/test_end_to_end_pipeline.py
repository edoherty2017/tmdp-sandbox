"""End-to-end integration test: EventSpec → MLCommandClassifier → T-MDP → SecurityEpisodeResult.

These tests use a classifier trained on small synthetic data so they run fast
without touching the disk-resident model files. They exercise the full
three-phase pipeline:
  Phase 1: baseline integrity check + context-window features
  Phase 2: ML classifier → P(malicious)
  Phase 3: T-MDP value iteration → EXECUTE/BLOCK/DEFER action
"""

from __future__ import annotations

import pytest

from tmdp_sandbox.classifier import MLCommandClassifier, train_classifier
from tmdp_sandbox.event_spec import EventSpec, SecurityScenario
from tmdp_sandbox.policies import (
    build_security_sequential_policy,
    build_security_tmdp_no_defer_policy,
    build_security_tmdp_policy,
    build_security_threshold_policy,
)
from tmdp_sandbox.preprocessing import extract_features_for_sequence
from tmdp_sandbox.security_runner import run_security_episode


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _benign(n: int = 30, offset: int = 0) -> list[EventSpec]:
    return [
        EventSpec(
            process_name="svchost.exe",
            command_line=f"C:\\Windows\\system32\\svchost.exe -k netsvcs {i+offset}",
            user_name="NT AUTHORITY\\SYSTEM",
            parent_process="services.exe",
            event_id=1,
            label="benign",
        )
        for i in range(n)
    ]


def _malicious(n: int = 30, offset: int = 0) -> list[EventSpec]:
    return [
        EventSpec(
            process_name="powershell.exe",
            command_line=f"powershell.exe -noprofile -enc aQBlAHgA{i+offset:04d}",
            user_name="user",
            parent_process="cmd.exe",
            event_id=1,
            label="malicious",
        )
        for i in range(n)
    ]


@pytest.fixture(scope="module")
def trained_classifier() -> MLCommandClassifier:
    train_events = _benign(40) + _malicious(40)
    fd, labels = extract_features_for_sequence(train_events)
    pipeline = train_classifier(fd, labels, model="logistic")
    return MLCommandClassifier(pipeline, window_size=5)


@pytest.fixture
def benign_scenario() -> SecurityScenario:
    events = tuple(_benign(5))
    return SecurityScenario(
        scenario_id="benign-e2e",
        seed=0,
        events=events,
        requested_executions=tuple(range(5)),
    )


@pytest.fixture
def malicious_scenario() -> SecurityScenario:
    events = tuple(_malicious(5))
    return SecurityScenario(
        scenario_id="malicious-e2e",
        seed=0,
        events=events,
        requested_executions=tuple(range(5)),
    )


@pytest.fixture
def mixed_scenario() -> SecurityScenario:
    # benign, benign, malicious, benign, benign
    events = tuple(_benign(2) + _malicious(1) + _benign(2))
    return SecurityScenario(
        scenario_id="mixed-e2e",
        seed=0,
        events=events,
        requested_executions=tuple(range(5)),
    )


# ---------------------------------------------------------------------------
# Phase 2 tests: classifier scores
# ---------------------------------------------------------------------------

def test_classifier_scores_benign_low(trained_classifier):
    event = _benign(1)[0]
    ctx = tuple(_benign(5))
    score = trained_classifier.score_event(event, ctx, decision_index=len(ctx) - 1)
    assert score < 0.5, f"expected low P(malicious) for benign event, got {score:.3f}"


def test_classifier_scores_malicious_high(trained_classifier):
    event = _malicious(1)[0]
    ctx = tuple(_malicious(5))
    score = trained_classifier.score_event(event, ctx, decision_index=len(ctx) - 1)
    assert score > 0.5, f"expected high P(malicious) for malicious event, got {score:.3f}"


# ---------------------------------------------------------------------------
# Phase 3 tests: T-MDP policy via build_security_tmdp_policy
# ---------------------------------------------------------------------------

def test_tmdp_policy_blocks_clearly_malicious(trained_classifier, malicious_scenario):
    policy = build_security_tmdp_policy(
        malicious_scenario,
        classifier=trained_classifier,
        compromise_cost=100.0,
        block_cost=5.0,
        execute_step_cost=1.0,
        defer_step_cost=0.5,
    )
    result = run_security_episode(
        scenario=malicious_scenario,
        policy=policy,
        episode_id="mal-tmdp",
        compromise_cost=100.0,
        block_cost=5.0,
        execute_step_cost=1.0,
        defer_step_cost=0.5,
    )
    assert result.malicious_executed is False, "T-MDP should block clearly malicious events"


def test_tmdp_policy_allows_clearly_benign(trained_classifier, benign_scenario):
    policy = build_security_tmdp_policy(
        benign_scenario,
        classifier=trained_classifier,
        compromise_cost=100.0,
        block_cost=5.0,
        execute_step_cost=1.0,
        defer_step_cost=0.5,
    )
    result = run_security_episode(
        scenario=benign_scenario,
        policy=policy,
        episode_id="ben-tmdp",
        compromise_cost=100.0,
        block_cost=5.0,
        execute_step_cost=1.0,
        defer_step_cost=0.5,
    )
    assert result.blocked_prematurely is False, (
        "T-MDP should not block an entirely benign sequence"
    )
    assert result.all_benign_allowed is True


# ---------------------------------------------------------------------------
# Threshold policy comparison
# ---------------------------------------------------------------------------

def test_threshold_policy_blocks_malicious(trained_classifier, malicious_scenario):
    policy = build_security_threshold_policy(
        malicious_scenario,
        classifier=trained_classifier,
        block_threshold=0.5,
    )
    result = run_security_episode(
        scenario=malicious_scenario,
        policy=policy,
        episode_id="mal-thresh",
    )
    assert result.malicious_executed is False


def test_threshold_policy_allows_benign(trained_classifier, benign_scenario):
    policy = build_security_threshold_policy(
        benign_scenario,
        classifier=trained_classifier,
        block_threshold=0.5,
    )
    result = run_security_episode(
        scenario=benign_scenario,
        policy=policy,
        episode_id="ben-thresh",
    )
    assert result.all_benign_allowed is True


# ---------------------------------------------------------------------------
# Full pipeline: mixed scenario
# ---------------------------------------------------------------------------

def test_tmdp_handles_mixed_scenario_without_crash(trained_classifier, mixed_scenario):
    policy = build_security_tmdp_policy(
        mixed_scenario,
        classifier=trained_classifier,
        compromise_cost=100.0,
        block_cost=5.0,
        execute_step_cost=1.0,
        defer_step_cost=0.5,
    )
    result = run_security_episode(
        scenario=mixed_scenario,
        policy=policy,
        episode_id="mixed-tmdp",
        compromise_cost=100.0,
        block_cost=5.0,
        execute_step_cost=1.0,
        defer_step_cost=0.5,
    )
    # Policy must complete without error and return a coherent result
    assert result.cumulative_cost >= 0.0
    assert 0.0 <= result.benign_allow_rate <= 1.0
    assert 0.0 <= result.malicious_block_rate <= 1.0


# ---------------------------------------------------------------------------
# No-defer variant: INSPECT_NEXT → BLOCK (no human deferral)
# ---------------------------------------------------------------------------

def test_no_defer_blocks_clearly_malicious(trained_classifier, malicious_scenario):
    policy = build_security_tmdp_no_defer_policy(
        malicious_scenario,
        classifier=trained_classifier,
        compromise_cost=100.0,
        block_cost=5.0,
        execute_step_cost=1.0,
    )
    result = run_security_episode(
        scenario=malicious_scenario,
        policy=policy,
        episode_id="mal-nodefer",
        compromise_cost=100.0,
        block_cost=5.0,
        execute_step_cost=1.0,
    )
    assert result.malicious_executed is False
    assert result.deferred_count == 0, "no-defer variant must never emit DEFER"


def test_no_defer_allows_clearly_benign(trained_classifier, benign_scenario):
    policy = build_security_tmdp_no_defer_policy(
        benign_scenario,
        classifier=trained_classifier,
        compromise_cost=100.0,
        block_cost=5.0,
        execute_step_cost=1.0,
    )
    result = run_security_episode(
        scenario=benign_scenario,
        policy=policy,
        episode_id="ben-nodefer",
        compromise_cost=100.0,
        block_cost=5.0,
        execute_step_cost=1.0,
    )
    assert result.all_benign_allowed is True
    assert result.deferred_count == 0


def test_nodefer_and_defer_agree_on_clearly_malicious(trained_classifier, malicious_scenario):
    """With high-confidence malicious events, both variants should block."""
    pol_defer = build_security_tmdp_policy(
        malicious_scenario, classifier=trained_classifier,
        compromise_cost=100.0, block_cost=5.0, execute_step_cost=1.0, defer_step_cost=0.5,
    )
    pol_nodefer = build_security_tmdp_no_defer_policy(
        malicious_scenario, classifier=trained_classifier,
        compromise_cost=100.0, block_cost=5.0, execute_step_cost=1.0,
    )
    r_defer = run_security_episode(scenario=malicious_scenario, policy=pol_defer,
                                   episode_id="agree-defer", compromise_cost=100.0)
    r_nodefer = run_security_episode(scenario=malicious_scenario, policy=pol_nodefer,
                                     episode_id="agree-nodefer", compromise_cost=100.0)
    assert r_defer.malicious_executed is False
    assert r_nodefer.malicious_executed is False


# ---------------------------------------------------------------------------
# Sequential policy: BLOCK_EVENT per event, episode continues
# ---------------------------------------------------------------------------

def test_sequential_policy_does_not_stop_episode_early(trained_classifier, mixed_scenario):
    """Sequential policy must process ALL events even after blocking a malicious one."""
    policy = build_security_sequential_policy(
        mixed_scenario,
        classifier=trained_classifier,
        compromise_cost=100.0,
        block_cost=5.0,
        execute_step_cost=1.0,
        defer_step_cost=0.5,
    )
    # Policy should have one output per requested execution (not truncated at first block)
    n_decisions = len(mixed_scenario.requested_executions)
    assert len(policy.outputs) == n_decisions, (
        f"sequential policy must emit {n_decisions} decisions, got {len(policy.outputs)}"
    )


def test_sequential_policy_emits_block_event_not_block(trained_classifier, malicious_scenario):
    """For clearly malicious events, sequential policy should use BLOCK_EVENT."""
    policy = build_security_sequential_policy(
        malicious_scenario,
        classifier=trained_classifier,
        compromise_cost=100.0,
        block_cost=5.0,
        execute_step_cost=1.0,
        defer_step_cost=0.5,
    )
    outputs_upper = [o.upper() for o in policy.outputs]
    has_block_event = any(o.startswith("BLOCK_EVENT") for o in outputs_upper)
    has_block_all = any(o == "BLOCK" or o.startswith("BLOCK ") for o in outputs_upper)
    assert has_block_event, "sequential policy should emit BLOCK_EVENT for malicious events"
    assert not has_block_all, "sequential policy must not emit all-stop BLOCK"


def test_sequential_policy_blocks_malicious_correctly(trained_classifier, malicious_scenario):
    """Sequential policy must not allow any malicious event to execute."""
    policy = build_security_sequential_policy(
        malicious_scenario,
        classifier=trained_classifier,
        compromise_cost=100.0,
        block_cost=5.0,
        execute_step_cost=1.0,
        defer_step_cost=0.5,
    )
    result = run_security_episode(
        scenario=malicious_scenario,
        policy=policy,
        episode_id="mal-sequential",
        compromise_cost=100.0,
        block_cost=5.0,
        execute_step_cost=1.0,
    )
    assert result.malicious_executed is False


def test_sequential_policy_processes_all_events_after_malicious(trained_classifier):
    """Sequential policy must produce an output for every event, including those after a malicious one.

    Scenario: benign, MALICIOUS, benign, benign.
    Stop-on-first would truncate outputs at index 1 and never emit decisions for 2, 3.
    Sequential must emit exactly 4 decisions and must not use the all-stop BLOCK token.
    Whether the classifier admits the post-malicious benign events depends on context
    window features (which may be elevated after a malicious event) — that is a
    classifier quality question tested separately. The architectural invariant is
    simply that the policy does not short-circuit.
    """
    events = tuple(_benign(1) + _malicious(1) + _benign(2))
    scenario = SecurityScenario(
        scenario_id="post-malicious-benign",
        seed=7,
        events=events,
        requested_executions=(0, 1, 2, 3),
    )
    policy = build_security_sequential_policy(
        scenario,
        classifier=trained_classifier,
        compromise_cost=100.0,
        block_cost=5.0,
        execute_step_cost=1.0,
        defer_step_cost=0.5,
    )
    # All 4 events must be decided (no early stop)
    assert len(policy.outputs) == 4, (
        f"sequential policy must emit 4 decisions, got {len(policy.outputs)}: {policy.outputs}"
    )
    # Must not use all-stop BLOCK (only BLOCK_EVENT is allowed for refusals)
    stop_tokens = [o for o in policy.outputs if o.upper() == "BLOCK" or
                   (o.upper().startswith("BLOCK ") and not o.upper().startswith("BLOCK_EVENT"))]
    assert not stop_tokens, f"sequential policy must not emit all-stop BLOCK: {stop_tokens}"
    # Malicious event (index 1) must not be executed
    assert not policy.outputs[1].upper().startswith("EXECUTE"), (
        "malicious event at index 1 should be blocked"
    )


def test_block_event_runner_does_not_stop_episode():
    """Runner: BLOCK_EVENT action costs c_block but does not end the episode."""
    events = (
        EventSpec(process_name="svchost.exe", command_line="svc", user_name="SYSTEM",
                  parent_process="services.exe", event_id=4688, label="benign"),
        EventSpec(process_name="powershell.exe", command_line="pwsh -enc abc",
                  user_name="user", parent_process="cmd.exe", event_id=4688, label="malicious"),
        EventSpec(process_name="svchost.exe", command_line="svc2", user_name="SYSTEM",
                  parent_process="services.exe", event_id=4688, label="benign"),
    )
    scenario = SecurityScenario(
        scenario_id="block-event-runner-test",
        seed=0,
        events=events,
        requested_executions=(0, 1, 2),
    )
    from tmdp_sandbox.security_runner import SecurityScriptedPolicy
    policy = SecurityScriptedPolicy(
        policy_id="manual",
        outputs=("EXECUTE 0", "BLOCK_EVENT 1", "EXECUTE 2"),
        risk_estimates=(0.0, 1.0, 0.0),
    )
    result = run_security_episode(
        scenario=scenario, policy=policy, episode_id="bev-test",
        compromise_cost=100.0, block_cost=5.0, execute_step_cost=1.0,
    )
    assert result.malicious_executed is False, "BLOCK_EVENT must not let the malicious event slip"
    assert result.benign_allow_rate == pytest.approx(1.0), "both benign events must execute"
    assert result.steps == 3, "all 3 steps must be processed"
    # cost = c_execute + c_block + c_execute = 1 + 5 + 1 = 7
    assert result.cumulative_cost == pytest.approx(7.0)
