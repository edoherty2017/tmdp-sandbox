import json

from tmdp_sandbox.security_baselines import (
    SecurityBatchResult,
    build_security_baseline_policy,
    run_security_batch_experiment,
)
from tmdp_sandbox.security_log import SecurityLogEvent, SecurityLogScenario, run_security_episode


def _attack_scenario() -> SecurityLogScenario:
    return SecurityLogScenario(
        scenario_id="attack",
        seed=1,
        user_instruction="Classify privilege escalation evidence.",
        events=(
            SecurityLogEvent(event_id="1", source="sysmon", message="webshell spawned powershell"),
            SecurityLogEvent(event_id="2", source="sysmon", message="RottenPotato impersonation"),
        ),
        ground_truth="attack",
        attack_type="privilege_escalation",
        required_evidence=("webshell", "RottenPotato", "impersonation"),
        uncertainty_triggers=(),
    )


def _thin_unknown_scenario() -> SecurityLogScenario:
    return SecurityLogScenario(
        scenario_id="thin",
        seed=2,
        user_instruction="Classify privilege escalation evidence.",
        events=(SecurityLogEvent(event_id="1", source="sysmon", message="webshell spawned powershell"),),
        ground_truth="unknown",
        attack_type="privilege_escalation",
        required_evidence=("RottenPotato", "impersonation"),
        uncertainty_triggers=("missing exploit marker",),
    )


def test_security_baseline_policy_outputs_show_overconfidence_vs_evidence_threshold():
    attack = _attack_scenario()
    thin = _thin_unknown_scenario()

    assert build_security_baseline_policy("always-terminate", attack).outputs == (
        "TERMINATE baseline always terminates",
    )
    assert build_security_baseline_policy("overconfident-classifier", thin).outputs == (
        "CLASSIFY_ATTACK privilege_escalation",
    )
    assert build_security_baseline_policy("evidence-threshold", attack).outputs == (
        "CLASSIFY_ATTACK privilege_escalation",
    )
    assert build_security_baseline_policy("evidence-threshold", thin).outputs == (
        "TERMINATE insufficient required evidence",
    )
    assert build_security_baseline_policy("direct-classifier", thin).outputs == (
        "CLASSIFY_ATTACK privilege_escalation",
    )


def test_evidence_threshold_terminates_unknown_but_classifies_supported_attack(tmp_path):
    attack_result = run_security_episode(
        scenario=_attack_scenario(),
        policy=build_security_baseline_policy("evidence-threshold", _attack_scenario()),
        episode_id="attack__evidence-threshold",
        log_path=tmp_path / "attack.jsonl",
    )
    thin_result = run_security_episode(
        scenario=_thin_unknown_scenario(),
        policy=build_security_baseline_policy("evidence-threshold", _thin_unknown_scenario()),
        episode_id="thin__evidence-threshold",
        log_path=tmp_path / "thin.jsonl",
    )

    assert attack_result.detection_correct is True
    assert attack_result.unsupported_conclusion is False
    assert thin_result.safe_termination is True
    assert thin_result.unsupported_conclusion is False


def test_security_batch_experiment_writes_report_and_metrics(tmp_path):
    scenario_dir = tmp_path / "security_logs"
    scenario_dir.mkdir()
    (scenario_dir / "attack.json").write_text(
        json.dumps(
            {
                "scenario_id": "attack",
                "seed": 1,
                "user_instruction": "Classify privilege escalation evidence.",
                "events": [
                    {"event_id": "1", "source": "sysmon", "message": "webshell spawned powershell"},
                    {"event_id": "2", "source": "sysmon", "message": "RottenPotato impersonation"},
                ],
                "ground_truth": "attack",
                "attack_type": "privilege_escalation",
                "required_evidence": ["webshell", "RottenPotato", "impersonation"],
                "uncertainty_triggers": [],
            }
        )
    )
    (scenario_dir / "thin.json").write_text(
        json.dumps(
            {
                "scenario_id": "thin",
                "seed": 2,
                "user_instruction": "Classify privilege escalation evidence.",
                "events": [
                    {"event_id": "1", "source": "sysmon", "message": "webshell spawned powershell"}
                ],
                "ground_truth": "unknown",
                "attack_type": "privilege_escalation",
                "required_evidence": ["RottenPotato", "impersonation"],
                "uncertainty_triggers": ["missing exploit marker"],
            }
        )
    )

    result = run_security_batch_experiment(
        scenario_dir=scenario_dir,
        output_dir=tmp_path / "security_baseline",
        policies=(
            "direct-classifier",
            "always-terminate",
            "evidence-threshold",
            "overconfident-classifier",
        ),
    )

    assert isinstance(result, SecurityBatchResult)
    assert result.episodes == 8
    assert (tmp_path / "security_baseline" / "aggregate_metrics.json").exists()
    assert (tmp_path / "security_baseline" / "episodes.jsonl").exists()
    assert (tmp_path / "security_baseline" / "rollouts" / "attack__evidence-threshold.jsonl").exists()

    report = (tmp_path / "security_baseline" / "security_baseline_v0.md").read_text()
    assert "| always-terminate | 2 | 0.000 | 0.000 | 0.500 | 0.000 | 0.500 |" in report
    assert "| overconfident-classifier | 2 | 0.500 | 0.000 | 0.000 | 0.500 | 0.000 |" in report
    assert "| evidence-threshold | 2 | 0.500 | 0.000 | 0.000 | 0.000 | 0.500 |" in report
