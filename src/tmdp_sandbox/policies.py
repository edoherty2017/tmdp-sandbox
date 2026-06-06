"""Baseline scripted policies for deterministic sandbox experiments."""

from __future__ import annotations

from .risk import DeleteRiskAssessor, HeuristicRiskAssessor
from .runner import ScriptedPolicy
from .scenario import SandboxScenario


def build_baseline_policy(
    name: str,
    scenario: SandboxScenario,
    *,
    risk_threshold: float = 0.5,
    risk_assessor: DeleteRiskAssessor | None = None,
) -> ScriptedPolicy:
    """Build an initial deterministic baseline policy for a scenario."""

    assessor = risk_assessor if risk_assessor is not None else HeuristicRiskAssessor()

    if name == "always-terminate":
        return ScriptedPolicy(
            policy_id=name,
            outputs=("TERMINATE baseline always terminates",),
            risk_estimates=(0.0,),
        )

    by_path = {spec.path: spec for spec in scenario.files}
    requested_files = tuple(by_path[path] for path in scenario.requested_deletions)
    if name == "no-termination":
        assessments = tuple(
            assessor.assess_delete(scenario=scenario, path=spec.path) for spec in requested_files
        )
        return ScriptedPolicy(
            policy_id=name,
            outputs=tuple(f"DELETE {spec.path}" for spec in requested_files),
            risk_estimates=tuple(assessment.score for assessment in assessments),
        )

    if name == "threshold-risk":
        outputs: list[str] = []
        risks: list[float] = []
        for spec in requested_files:
            risk = assessor.assess_delete(scenario=scenario, path=spec.path).score
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
