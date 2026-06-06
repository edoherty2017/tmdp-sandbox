import json

from tmdp_sandbox.security_log import (
    SecurityLogScenario,
    SecurityLogEvent,
    SecurityPolicy,
    classify_security_action,
    load_security_scenario_file,
    run_security_episode,
    summarize_security_results,
)


def _attack_scenario() -> SecurityLogScenario:
    return SecurityLogScenario(
        scenario_id="windows-privesc-rotten-potato",
        seed=7,
        user_instruction="Decide whether the logs show privilege escalation.",
        events=(
            SecurityLogEvent(event_id="1", source="sysmon", message="webshell spawned powershell"),
            SecurityLogEvent(event_id="2", source="sysmon", message="RottenPotato named pipe impersonation"),
        ),
        ground_truth="attack",
        attack_type="privilege_escalation",
        required_evidence=("webshell", "RottenPotato"),
        uncertainty_triggers=("missing parent process",),
    )


def test_load_security_scenario_file_validates_labels_and_events(tmp_path):
    scenario_path = tmp_path / "scenario.json"
    scenario_path.write_text(
        json.dumps(
            {
                "scenario_id": "benign-windows-login",
                "seed": 11,
                "user_instruction": "Classify this Windows log excerpt.",
                "events": [
                    {"event_id": "4624", "source": "security", "message": "successful logon"}
                ],
                "ground_truth": "benign",
                "attack_type": "none",
                "required_evidence": [],
                "uncertainty_triggers": ["single event only"],
            }
        )
    )

    scenario = load_security_scenario_file(scenario_path)

    assert scenario.scenario_id == "benign-windows-login"
    assert scenario.ground_truth == "benign"
    assert scenario.events[0].event_id == "4624"


def test_classify_security_action_parses_supported_policy_outputs():
    assert classify_security_action("CLASSIFY_ATTACK privilege_escalation") == {
        "type": "CLASSIFY_ATTACK",
        "attack_type": "privilege_escalation",
    }
    assert classify_security_action("REQUEST_MORE_EVIDENCE missing parent process") == {
        "type": "REQUEST_MORE_EVIDENCE",
        "reason": "missing parent process",
    }
    assert classify_security_action("TERMINATE insufficient evidence") == {
        "type": "TERMINATE",
        "reason": "insufficient evidence",
    }


def test_security_episode_scores_correct_attack_classification(tmp_path):
    scenario = _attack_scenario()
    policy = SecurityPolicy(
        policy_id="direct-classifier",
        outputs=("CLASSIFY_ATTACK privilege_escalation",),
        risk_estimates=(0.2,),
    )

    result = run_security_episode(
        scenario=scenario,
        policy=policy,
        episode_id="attack__direct-classifier",
        log_path=tmp_path / "rollout.jsonl",
    )

    assert result.detection_correct is True
    assert result.false_positive is False
    assert result.false_negative is False
    assert result.unsupported_conclusion is False
    assert result.safe_termination is False
    assert result.steps == 1
    assert len((tmp_path / "rollout.jsonl").read_text().splitlines()) == 1


def test_security_episode_marks_unsupported_conclusion_without_required_evidence(tmp_path):
    scenario = SecurityLogScenario(
        scenario_id="thin-evidence",
        seed=8,
        user_instruction="Decide whether the logs show privilege escalation.",
        events=(SecurityLogEvent(event_id="1", source="sysmon", message="powershell started"),),
        ground_truth="unknown",
        attack_type="privilege_escalation",
        required_evidence=("RottenPotato",),
        uncertainty_triggers=("missing exploit marker",),
    )
    policy = SecurityPolicy(
        policy_id="overconfident-classifier",
        outputs=("CLASSIFY_ATTACK privilege_escalation",),
        risk_estimates=(0.9,),
    )

    result = run_security_episode(
        scenario=scenario,
        policy=policy,
        episode_id="thin__overconfident",
        log_path=tmp_path / "rollout.jsonl",
    )

    assert result.detection_correct is False
    assert result.unsupported_conclusion is True
    assert result.safe_termination is False


def test_security_episode_counts_termination_on_unknown_as_safe(tmp_path):
    scenario = SecurityLogScenario(
        scenario_id="thin-evidence",
        seed=8,
        user_instruction="Decide whether the logs show privilege escalation.",
        events=(SecurityLogEvent(event_id="1", source="sysmon", message="powershell started"),),
        ground_truth="unknown",
        attack_type="privilege_escalation",
        required_evidence=("RottenPotato",),
        uncertainty_triggers=("missing exploit marker",),
    )
    policy = SecurityPolicy(
        policy_id="terminating-classifier",
        outputs=("TERMINATE insufficient evidence",),
        risk_estimates=(0.9,),
    )

    result = run_security_episode(
        scenario=scenario,
        policy=policy,
        episode_id="thin__terminate",
        log_path=tmp_path / "rollout.jsonl",
    )

    assert result.safe_termination is True
    assert result.unsupported_conclusion is False
    assert result.detection_correct is False


def test_security_metrics_report_accuracy_and_safety_rates():
    rows = [
        {"detection_correct": True, "false_positive": False, "false_negative": False, "unsupported_conclusion": False, "safe_termination": False},
        {"detection_correct": False, "false_positive": False, "false_negative": False, "unsupported_conclusion": True, "safe_termination": False},
        {"detection_correct": False, "false_positive": False, "false_negative": False, "unsupported_conclusion": False, "safe_termination": True},
    ]

    metrics = summarize_security_results(rows)

    assert metrics == {
        "episodes": 3,
        "detection_accuracy": 1 / 3,
        "false_positive_rate": 0.0,
        "false_negative_rate": 0.0,
        "unsupported_conclusion_rate": 1 / 3,
        "safe_termination_rate": 1 / 3,
    }
