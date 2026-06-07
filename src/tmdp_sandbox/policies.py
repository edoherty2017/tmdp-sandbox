"""Baseline scripted policies for deterministic sandbox experiments."""

from __future__ import annotations

from .risk import DeleteRiskAssessor, OracleLabelRiskAssessor
from .runner import ScriptedPolicy
from .scenario import SandboxScenario
from .tmdp_model import RiskBin, TMDPModel
from .value_iteration import greedy_action, value_iteration


def build_baseline_policy(
    name: str,
    scenario: SandboxScenario,
    *,
    risk_threshold: float = 0.5,
    risk_assessor: DeleteRiskAssessor | None = None,
) -> ScriptedPolicy:
    """Build an initial deterministic baseline policy for a scenario."""

    assessor = risk_assessor if risk_assessor is not None else OracleLabelRiskAssessor()

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


def build_tmdp_value_iteration_policy(
    scenario: SandboxScenario,
    *,
    observable_risk_by_path: dict[str, RiskBin],
    p_catastrophic_by_path: dict[str, float],
    inspection_observations_by_path: dict[str, dict[RiskBin, tuple[float, float]]] | None = None,
    catastrophe_cost: float = 100.0,
    termination_cost: float = 5.0,
    delete_step_cost: float = 1.0,
    inspect_step_cost: float = 0.25,
    completion_cost: float = 0.0,
) -> ScriptedPolicy:
    """Build the first finite-state value-iteration policy adapter.

    This milestone-1 adapter evaluates requested deletions in order with a
    one-step belief-state T-MDP per candidate. It consumes observable risk bins
    and catastrophe beliefs; it does not read hidden fixture labels when
    constructing the Bellman model.
    """

    by_path = {spec.path: spec for spec in scenario.files}
    outputs: list[str] = []
    risks: list[float] = []
    for target_path in scenario.requested_deletions:
        if target_path not in by_path:
            raise ValueError(f"requested deletion not present in fixture files: {target_path!r}")
        if target_path not in observable_risk_by_path:
            raise ValueError(f"missing observable risk bin for requested deletion: {target_path!r}")
        if target_path not in p_catastrophic_by_path:
            raise ValueError(f"missing catastrophe belief for requested deletion: {target_path!r}")

        inspection_observations = (
            inspection_observations_by_path.get(target_path)
            if inspection_observations_by_path is not None
            else None
        )
        model = TMDPModel.single_candidate(
            p_catastrophic=p_catastrophic_by_path[target_path],
            observable_risk_bin=observable_risk_by_path[target_path],
            inspection_observations=inspection_observations,
            catastrophe_cost=catastrophe_cost,
            termination_cost=termination_cost,
            delete_step_cost=delete_step_cost,
            inspect_step_cost=inspect_step_cost,
            completion_cost=completion_cost,
        )
        _, policy = value_iteration(model)
        action = greedy_action(policy, model.initial_state)
        risks.append(p_catastrophic_by_path[target_path])
        if action == "DELETE_NEXT":
            outputs.append(f"DELETE {target_path}")
            continue
        if action == "TERMINATE":
            outputs.append("TERMINATE tmdp expected-cost policy")
            return ScriptedPolicy(
                policy_id="tmdp-value-iteration",
                outputs=tuple(outputs),
                risk_estimates=tuple(risks),
            )
        outputs.append("TERMINATE tmdp inspect action not supported by scripted runner")
        return ScriptedPolicy(
            policy_id="tmdp-value-iteration",
            outputs=tuple(outputs),
            risk_estimates=tuple(risks),
        )

    return ScriptedPolicy(
        policy_id="tmdp-value-iteration",
        outputs=tuple(outputs) if outputs else ("TERMINATE tmdp no requested deletions",),
        risk_estimates=tuple(risks) if risks else (0.0,),
    )


def _risk_score(risk_bin: RiskBin) -> float:
    return {"low": 0.1, "medium": 0.5, "high": 0.9}[risk_bin]
