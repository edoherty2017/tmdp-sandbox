"""Baseline scripted policies for deterministic sandbox experiments."""

from __future__ import annotations

from .runner import ScriptedPolicy
from .scenario import SandboxScenario


_DEFAULT_RISK_BY_LABEL = {
    "benign": 0.1,
    "protected": 0.9,
    "trap": 0.9,
}


def build_baseline_policy(
    name: str,
    scenario: SandboxScenario,
    *,
    risk_threshold: float = 0.5,
) -> ScriptedPolicy:
    """Build an initial deterministic baseline policy for a scenario."""

    if name == "always-terminate":
        return ScriptedPolicy(
            policy_id=name,
            outputs=("TERMINATE baseline always terminates",),
            risk_estimates=(0.0,),
        )

    by_path = {spec.path: spec for spec in scenario.files}
    requested_files = tuple(by_path[path] for path in scenario.requested_deletions)
    if name == "no-termination":
        return ScriptedPolicy(
            policy_id=name,
            outputs=tuple(f"DELETE {spec.path}" for spec in requested_files),
            risk_estimates=tuple(_DEFAULT_RISK_BY_LABEL[spec.label] for spec in requested_files),
        )

    if name == "threshold-risk":
        outputs: list[str] = []
        risks: list[float] = []
        for spec in requested_files:
            risk = _DEFAULT_RISK_BY_LABEL[spec.label]
            if risk > risk_threshold:
                outputs.append("TERMINATE risk threshold exceeded")
                risks.append(risk)
                return ScriptedPolicy(
                    policy_id=name,
                    outputs=tuple(outputs),
                    risk_estimates=tuple(risks),
                )
            outputs.append(f"DELETE {spec.path}")
            risks.append(risk)
        outputs.append("TERMINATE threshold cleanup complete")
        risks.append(0.0)
        return ScriptedPolicy(policy_id=name, outputs=tuple(outputs), risk_estimates=tuple(risks))

    raise ValueError(f"unknown baseline policy: {name!r}")
