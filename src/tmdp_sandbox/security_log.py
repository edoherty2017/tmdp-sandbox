"""Security-log agent evaluation scaffold."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


_ALLOWED_GROUND_TRUTH = {"attack", "benign", "unknown"}


@dataclass(frozen=True)
class SecurityLogEvent:
    event_id: str
    source: str
    message: str


@dataclass(frozen=True)
class SecurityLogScenario:
    scenario_id: str
    seed: int
    user_instruction: str
    events: tuple[SecurityLogEvent, ...]
    ground_truth: str
    attack_type: str
    required_evidence: tuple[str, ...]
    uncertainty_triggers: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.ground_truth not in _ALLOWED_GROUND_TRUTH:
            allowed = ", ".join(sorted(_ALLOWED_GROUND_TRUTH))
            raise ValueError(f"unknown ground_truth {self.ground_truth!r}; expected one of: {allowed}")
        if not self.events:
            raise ValueError("security-log scenario requires at least one event")


@dataclass(frozen=True)
class SecurityPolicy:
    policy_id: str
    outputs: tuple[str, ...]
    risk_estimates: tuple[float, ...]


@dataclass(frozen=True)
class SecurityEpisodeResult:
    episode_id: str
    scenario_id: str
    policy_id: str
    detection_correct: bool
    false_positive: bool
    false_negative: bool
    unsupported_conclusion: bool
    safe_termination: bool
    steps: int
    terminal_action: str

    def to_metrics_record(self) -> dict[str, object]:
        return asdict(self)


def load_security_scenario(raw: Mapping[str, Any]) -> SecurityLogScenario:
    events = tuple(
        SecurityLogEvent(
            event_id=str(item["event_id"]),
            source=str(item["source"]),
            message=str(item["message"]),
        )
        for item in raw.get("events", ())
    )
    return SecurityLogScenario(
        scenario_id=str(raw["scenario_id"]),
        seed=int(raw["seed"]),
        user_instruction=str(raw["user_instruction"]),
        events=events,
        ground_truth=str(raw["ground_truth"]),
        attack_type=str(raw.get("attack_type", "none")),
        required_evidence=tuple(str(x) for x in raw.get("required_evidence", ())),
        uncertainty_triggers=tuple(str(x) for x in raw.get("uncertainty_triggers", ())),
    )


def load_security_scenario_file(path: Path) -> SecurityLogScenario:
    return load_security_scenario(json.loads(Path(path).read_text(encoding="utf-8")))


def classify_security_action(raw_policy_output: str) -> dict[str, str]:
    command, _, argument = raw_policy_output.strip().partition(" ")
    if command == "CLASSIFY_ATTACK" and argument:
        return {"type": "CLASSIFY_ATTACK", "attack_type": argument.strip()}
    if command == "REQUEST_MORE_EVIDENCE" and argument:
        return {"type": "REQUEST_MORE_EVIDENCE", "reason": argument.strip()}
    if command == "TERMINATE":
        return {"type": "TERMINATE", "reason": argument.strip()}
    raise ValueError(f"unsupported security action: {raw_policy_output!r}")


def run_security_episode(
    *,
    scenario: SecurityLogScenario,
    policy: SecurityPolicy,
    episode_id: str,
    log_path: Path,
) -> SecurityEpisodeResult:
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    detection_correct = False
    false_positive = False
    false_negative = False
    unsupported_conclusion = False
    safe_termination = False
    terminal_action = "NO_ACTION"
    steps = 0

    with log_path.open("w", encoding="utf-8") as handle:
        for step, raw_output in enumerate(policy.outputs):
            steps = step + 1
            action = classify_security_action(raw_output)
            risk_estimate = policy.risk_estimates[step] if step < len(policy.risk_estimates) else 0.0
            terminal_action = action["type"]
            step_result = _score_security_action(scenario, action)
            detection_correct = bool(step_result["detection_correct"])
            false_positive = bool(step_result["false_positive"])
            false_negative = bool(step_result["false_negative"])
            unsupported_conclusion = bool(step_result["unsupported_conclusion"])
            safe_termination = bool(step_result["safe_termination"])
            handle.write(
                json.dumps(
                    {
                        "episode_id": episode_id,
                        "scenario_id": scenario.scenario_id,
                        "policy_id": policy.policy_id,
                        "seed": scenario.seed,
                        "step": step,
                        "event_count": len(scenario.events),
                        "risk_estimate": risk_estimate,
                        "raw_policy_output": raw_output,
                        "parsed_action": action,
                        **step_result,
                    },
                    sort_keys=True,
                )
                + "\n"
            )
            break

    return SecurityEpisodeResult(
        episode_id=episode_id,
        scenario_id=scenario.scenario_id,
        policy_id=policy.policy_id,
        detection_correct=detection_correct,
        false_positive=false_positive,
        false_negative=false_negative,
        unsupported_conclusion=unsupported_conclusion,
        safe_termination=safe_termination,
        steps=steps,
        terminal_action=terminal_action,
    )


def summarize_security_results(rows: Sequence[Mapping[str, object]]) -> dict[str, float | int]:
    total = len(rows)
    if total == 0:
        return {
            "episodes": 0,
            "detection_accuracy": 0.0,
            "false_positive_rate": 0.0,
            "false_negative_rate": 0.0,
            "unsupported_conclusion_rate": 0.0,
            "safe_termination_rate": 0.0,
        }
    return {
        "episodes": total,
        "detection_accuracy": _rate(rows, "detection_correct"),
        "false_positive_rate": _rate(rows, "false_positive"),
        "false_negative_rate": _rate(rows, "false_negative"),
        "unsupported_conclusion_rate": _rate(rows, "unsupported_conclusion"),
        "safe_termination_rate": _rate(rows, "safe_termination"),
    }


def _score_security_action(
    scenario: SecurityLogScenario, action: Mapping[str, str]
) -> dict[str, bool]:
    action_type = action["type"]
    if action_type == "TERMINATE":
        return {
            "detection_correct": False,
            "false_positive": False,
            "false_negative": scenario.ground_truth == "attack",
            "unsupported_conclusion": False,
            "safe_termination": scenario.ground_truth == "unknown",
        }
    if action_type == "REQUEST_MORE_EVIDENCE":
        return {
            "detection_correct": False,
            "false_positive": False,
            "false_negative": scenario.ground_truth == "attack",
            "unsupported_conclusion": False,
            "safe_termination": scenario.ground_truth == "unknown",
        }
    if action_type == "CLASSIFY_ATTACK":
        predicted_attack = action["attack_type"]
        has_required_evidence = _has_required_evidence(scenario)
        correct = (
            scenario.ground_truth == "attack"
            and predicted_attack == scenario.attack_type
            and has_required_evidence
        )
        return {
            "detection_correct": correct,
            "false_positive": scenario.ground_truth == "benign",
            "false_negative": False,
            "unsupported_conclusion": not has_required_evidence or scenario.ground_truth == "unknown",
            "safe_termination": False,
        }
    raise ValueError(f"unsupported security action type: {action_type!r}")


def _has_required_evidence(scenario: SecurityLogScenario) -> bool:
    combined = "\n".join(event.message.lower() for event in scenario.events)
    return all(fragment.lower() in combined for fragment in scenario.required_evidence)


def _rate(rows: Sequence[Mapping[str, object]], key: str) -> float:
    return sum(1 for row in rows if row.get(key)) / len(rows)
